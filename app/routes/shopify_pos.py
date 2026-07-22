from datetime import datetime, timedelta
import asyncio
import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import re
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
import httpx
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Shop, ShopifyStore
from app.services import crypto

router = APIRouter(prefix="/shopify", tags=["shopify-pos"])
logger = logging.getLogger(__name__)

TOKEN_REFRESH_BUFFER_SECONDS = 300
# When `search` is used without an explicit date range, how far back to
# pull orders from Shopify before filtering. Without this, an un-scoped
# search would fetch this store's entire order history on every keystroke.
DEFAULT_SEARCH_LOOKBACK_DAYS = 30
# GraphQL requires an explicit page size — REST's implicit "give me
# everything in range" doesn't exist. 100 covers a normal day's volume for
# one location; a location doing more than that in one search window would
# need cursor pagination, which isn't implemented yet (TODO below).
ORDERS_PAGE_SIZE = 100


# ─── Request schemas ────────────────────────────────────────────────────────
class LinkShopLocationRequest(BaseModel):
    shop_id: int
    location_id: str


class UnlinkShopLocationRequest(BaseModel):
    shop_id: int


# ─── Webhook signature verification ────────────────────────────────────────────
def verify_webhook_hmac(body: bytes, hmac_header: str) -> bool:
    """
    Confirms a webhook really came from Shopify and wasn't tampered with in
    transit. Shopify signs the raw request body with our client secret and
    sends the signature in a header — we recompute it ourselves and compare.
    """
    if not hmac_header:
        return False
    digest = hmac_lib.new(
        settings.shopify_client_secret.encode(), body, hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode()
    return hmac_lib.compare_digest(computed_hmac, hmac_header)


# ─── Shop / store lookup ────────────────────────────────────────────────────
def get_shop_and_store(location_id: str, db: Session) -> tuple[Shop, ShopifyStore]:
    """
    Find the Shop for this Shopify location, and the ShopifyStore that holds
    its company's access token. Mirrors get_company_by_location_id in
    square.py, but Shopify's tokens live on a separate ShopifyStore table
    rather than directly on Company.
    """
    shop = db.query(Shop).filter(Shop.shopify_location_id == location_id).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found for this location")

    if not shop.shopify_store_id:
        raise HTTPException(status_code=400, detail="Shop is not connected to Shopify")

    store = db.query(ShopifyStore).filter(ShopifyStore.id == shop.shopify_store_id).first()
    if not store:
        raise HTTPException(status_code=400, detail="Shopify store not found")

    return shop, store


def get_shop_by_domain_and_location(shop_domain: str, location_id: Optional[str], db: Session) -> Optional[Shop]:
    """
    Used by the webhook handler to find which Shop a given order belongs to,
    from the shop_domain (header) + location_id (order body).
    """
    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_shop_domain == shop_domain
    ).first()
    if not store:
        return None

    query = db.query(Shop).filter(Shop.shopify_store_id == store.id)
    if location_id:
        query = query.filter(Shop.shopify_location_id == str(location_id))
    return query.first()


# ─── Shopify Admin API — token refresh ─────────────────────────────────────────
# Unchanged by the GraphQL migration — this hits Shopify's OAuth token
# endpoint directly, which is a separate concern from Admin API style.
async def refresh_access_token(shop_domain: str, refresh_token: str) -> dict:
    url = f"https://{shop_domain}/admin/oauth/access_token"
    payload = {
        "client_id": settings.shopify_client_id,
        "client_secret": settings.shopify_client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, data=payload)
        resp.raise_for_status()
        return resp.json()


async def ensure_valid_token(store: ShopifyStore, db: Session) -> str:
    """
    Return a valid Shopify access token for this store. Refreshes
    automatically if expired or within the buffer window, persisting the
    new token pair back to the database.
    """
    if not store.shopify_access_token_encrypted or not store.shopify_refresh_token_encrypted:
        raise HTTPException(status_code=400, detail="Store is not connected to Shopify")

    needs_refresh = True
    if store.access_token_expires_at:
        remaining = (store.access_token_expires_at - datetime.utcnow()).total_seconds()
        needs_refresh = remaining <= TOKEN_REFRESH_BUFFER_SECONDS

    if not needs_refresh:
        return crypto.decrypt(store.shopify_access_token_encrypted)

    try:
        refresh_token = crypto.decrypt(store.shopify_refresh_token_encrypted)
        token_data = await refresh_access_token(store.shopify_shop_domain, refresh_token)
    except Exception:
        logger.exception("Shopify token refresh failed for store %s", store.id)
        raise HTTPException(status_code=502, detail="Failed to refresh Shopify access token")

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Failed to refresh Shopify access token")

    store.shopify_access_token_encrypted = crypto.encrypt(access_token)
    expires_in = token_data.get("expires_in")
    if expires_in:
        store.access_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    db.add(store)
    db.commit()
    db.refresh(store)

    return access_token


# ─── Shopify Admin API — GraphQL ────────────────────────────────────────────
def to_gid(resource: str, numeric_id: str) -> str:
    """Builds a GraphQL global ID from a plain numeric id we store locally,
    e.g. to_gid('Order', '123') -> 'gid://shopify/Order/123'."""
    return f"gid://shopify/{resource}/{numeric_id}"


def raise_sanitized_shopify_error(exc: httpx.HTTPStatusError):
    """
    Logs Shopify's raw error response server-side (useful for debugging) but
    never forwards it verbatim to our own API clients — the raw body could
    contain internal Shopify details we don't want to expose. Status code is
    preserved since it's meaningful to the frontend (404 vs 4xx vs 5xx).
    """
    logger.error(
        "[shopify api error] status=%s body=%s", exc.response.status_code, exc.response.text
    )
    raise HTTPException(status_code=exc.response.status_code, detail="Shopify API request failed")


async def shopify_graphql(
    shop_domain: str, access_token: str, query: str, variables: Optional[dict] = None
) -> dict:
    """
    POSTs a query/mutation to Shopify's single GraphQL Admin API endpoint.
    Must stay async — a blocking call here would freeze the whole event
    loop, including every other location's live SSE stream, while in
    flight (same reason the old REST shopify_get had to be async).

    GraphQL returns HTTP 200 even when the query itself failed — real
    errors live in an `errors` array inside an otherwise-200 body, so we
    check that separately from HTTP-level failures.
    """
    url = f"https://{shop_domain}/admin/api/{settings.shopify_api_version}/graphql.json"
    headers = {"X-Shopify-Access-Token": access_token, "Content-Type": "application/json"}
    payload = {"query": query, "variables": variables or {}}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, json=payload)

    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise_sanitized_shopify_error(exc)

    body = resp.json()
    if body.get("errors"):
        logger.error("[shopify graphql error] errors=%s", body["errors"])
        raise HTTPException(status_code=502, detail="Shopify API request failed")

    return body.get("data") or {}


def sanitize_search_term(value: str) -> str:
    """
    Strips characters that have special meaning in Shopify's search query
    syntax (quotes, colons) from user-provided search input, so a search
    term can't break out of its intended filter term or inject additional
    filter clauses into the query string we build server-side.
    """
    return re.sub(r'["\':]', "", value).strip()


# ─── SSE client queues per location ────────────────────────────────────────────
# { location_id: [asyncio.Queue, ...] }  — one Queue per connected browser tab
sse_clients: dict = {}


def get_queues(location_id: str) -> list:
    return sse_clients.setdefault(location_id, [])


async def push_event(location_id: str, data: str):
    for queue in sse_clients.get(location_id, []):
        await queue.put(data)


def extract_transaction_fields(order: dict) -> dict:
    """
    Pull just what the live POS list view + tax-free refund flow need out of
    a full Shopify order webhook payload — not the whole thing, to keep what
    we push over SSE minimal (avoid broadcasting unnecessary customer PII).

    NOTE: this parses the REST-style JSON body Shopify sends to webhooks,
    which is unaffected by our Admin API calls moving to GraphQL — webhook
    payload shape is a separate contract. See extract_order_fields_from_graphql
    below for the equivalent used on GraphQL query responses.
    """
    return {
        "order_id": order.get("id"),
        "order_number": order.get("order_number") or order.get("name"),
        "location_id": order.get("location_id"),
        "currency": order.get("currency"),
        "total_price": order.get("total_price"),
        "total_tax": order.get("total_tax"),
        "tax_lines": order.get("tax_lines", []),
        "line_items": [
            {
                "title": item.get("title"),
                "quantity": item.get("quantity"),
                "price": item.get("price"),
                "tax_lines": item.get("tax_lines", []),
            }
            for item in order.get("line_items", [])
        ],
        "created_at": order.get("created_at"),
    }


def extract_order_fields_from_graphql(order: dict) -> dict:
    """
    Same output shape as extract_transaction_fields() above, but built from
    a GraphQL order node instead of a REST-style webhook payload — so the
    frontend gets an identical structure regardless of whether a
    transaction arrived via the live SSE stream or a GraphQL list/detail
    call.
    """
    def money(field: str) -> Optional[str]:
        return ((order.get(field) or {}).get("shopMoney") or {}).get("amount")

    def tax_lines(source: list) -> list:
        return [
            {
                "title": tl.get("title"),
                "rate": tl.get("rate"),
                "price": ((tl.get("priceSet") or {}).get("shopMoney") or {}).get("amount"),
            }
            for tl in source or []
        ]

    return {
        "order_id": order.get("legacyResourceId"),
        "order_number": order.get("name"),
        "location_id": (order.get("physicalLocation") or {}).get("legacyResourceId"),
        "currency": order.get("currencyCode"),
        "total_price": money("totalPriceSet"),
        "total_tax": money("totalTaxSet"),
        "tax_lines": tax_lines(order.get("taxLines")),
        "line_items": [
            {
                "title": edge["node"].get("title"),
                "quantity": edge["node"].get("quantity"),
                "price": ((edge["node"].get("originalUnitPriceSet") or {}).get("shopMoney") or {}).get("amount"),
                "tax_lines": tax_lines(edge["node"].get("taxLines")),
            }
            for edge in (order.get("lineItems") or {}).get("edges", [])
        ],
        "created_at": order.get("createdAt"),
    }


# ── 1. POST /shopify/webhook ────────────────────────────────────────────────
@router.post("/webhook")
async def shopify_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Receives orders/create and orders/paid events from Shopify. Verifies the
    HMAC signature, then — if the order came from a POS terminal — pushes
    the transaction to any connected SSE clients for that location.

    Unaffected by the REST->GraphQL migration: webhook payload shape is a
    separate contract from how we call the Admin API to fetch data.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_webhook_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Authenticated at this point (HMAC-verified) — anything that goes wrong
    # below is our problem, not Shopify's. Ack 200 regardless so Shopify
    # doesn't retry-storm or flag this webhook subscription as failing; we
    # log and handle failures on our side instead.
    try:
        shop_domain = request.headers.get("X-Shopify-Shop-Domain", "")

        try:
            order = json.loads(body)
        except (TypeError, ValueError):
            logger.warning("Invalid Shopify webhook payload from %s", shop_domain)
            return JSONResponse({"status": "ok", "ignored": True})

        # Only POS-originated orders matter for this stream — everything
        # else (online store, draft orders, etc.) is ignored here.
        if order.get("source_name") != "pos":
            return JSONResponse({"status": "ok", "ignored": True})

        location_id = str(order.get("location_id")) if order.get("location_id") else None
        if not location_id:
            return JSONResponse({"status": "ok", "ignored": True, "reason": "no location_id"})

        shop = get_shop_by_domain_and_location(shop_domain, location_id, db)
        if not shop:
            logger.warning(
                "Shopify webhook for unknown shop/location: domain=%s location=%s",
                shop_domain, location_id,
            )
            return JSONResponse({"status": "ok", "ignored": True, "reason": "shop not found"})

        transaction = extract_transaction_fields(order)
        await push_event(location_id, json.dumps(transaction))

        return JSONResponse({"status": "ok"})
    except Exception:
        logger.exception("Unhandled error processing Shopify webhook")
        return JSONResponse({"status": "ok"})


# ── 2. GET /shopify/stores/{store_id}/locations ─────────────────────────────
LOCATIONS_QUERY = """
query getLocations($first: Int!) {
  locations(first: $first) {
    edges {
      node {
        legacyResourceId
        name
        isActive
      }
    }
  }
}
"""


@router.get("/stores/{store_id}/locations")
async def get_store_locations(store_id: int, db: Session = Depends(get_db)):
    """
    Fetches this Shopify store's physical locations live from the Admin API,
    for the location-picker used by link-shop-location. Lives here, not in
    shopify.py, because it calls the Shopify API with an access token rather
    than just reading local DB linking state.

    NOTE: capped at 50 locations, no pagination — fine for the vast
    majority of stores. A store with more than 50 physical POS locations
    would need this extended to page through results.
    """
    store = db.query(ShopifyStore).filter(ShopifyStore.id == store_id).first()
    if not store:
        raise HTTPException(status_code=404, detail="Shopify store not found")

    access_token = await ensure_valid_token(store, db)

    data = await shopify_graphql(
        store.shopify_shop_domain, access_token, LOCATIONS_QUERY, {"first": 50}
    )

    return [
        {
            "id": edge["node"]["legacyResourceId"],
            "name": edge["node"].get("name"),
            "active": edge["node"].get("isActive"),
        }
        for edge in data.get("locations", {}).get("edges", [])
    ]


# ── 3. GET /shopify/events/{location_id} ────────────────────────────────────
@router.get("/events/{location_id}")
async def sse_events(location_id: str, request: Request, db: Session = Depends(get_db)):
    """
    SSE endpoint — store frontend connects here and keeps the connection
    open. Pushes a transaction the moment the webhook handler above
    receives it. Keepalive ping every 30s to survive proxy timeouts.

    TODO(auth): no ownership check yet — intentionally left unimplemented in
    this sandbox (auth/cookies belong to the real project). Before
    production, this must verify the requesting session actually owns
    `location_id`, same as square.py's verify_shop_owns_location.
    """
    shop, _ = get_shop_and_store(location_id, db)

    queue: asyncio.Queue = asyncio.Queue()
    get_queues(location_id).append(queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {"event": "new_transaction", "data": data}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": ""}
        except asyncio.CancelledError:
            pass
        finally:
            if queue in sse_clients.get(location_id, []):
                sse_clients[location_id].remove(queue)

    return EventSourceResponse(event_generator(), ping=20)


# ── 4. GET /shopify/orders/{location_id} ────────────────────────────────────
ORDERS_QUERY = """
query getOrders($first: Int!, $query: String!) {
  orders(first: $first, query: $query) {
    edges {
      node {
        legacyResourceId
        name
        createdAt
        currencyCode
        totalPriceSet { shopMoney { amount currencyCode } }
        totalTaxSet { shopMoney { amount currencyCode } }
        taxLines { title rate priceSet { shopMoney { amount currencyCode } } }
        lineItems(first: 50) {
          edges {
            node {
              title
              quantity
              originalUnitPriceSet { shopMoney { amount currencyCode } }
              taxLines { title rate priceSet { shopMoney { amount currencyCode } } }
            }
          }
        }
        physicalLocation { legacyResourceId }
      }
    }
  }
}
"""


@router.get("/orders/{location_id}")
async def get_orders(
    location_id: str,
    db: Session = Depends(get_db),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    search: Optional[str] = None,
):
    """
    On-demand order list for this location — used for initial page load,
    backfill, manual refresh, and search/typeahead, since the SSE stream
    only carries orders that arrive after the connection opens.

    `search` matches Shopify's human-facing order number (e.g. "#1001"),
    as a prefix match. If `search` is given without an explicit date
    range, defaults to the last DEFAULT_SEARCH_LOOKBACK_DAYS days rather
    than pulling this store's entire order history.

    Filters by location_id directly in the GraphQL query, then re-checks
    location on each returned order as defense in depth — the same
    principle as get_order_detail's ownership check below: never trust a
    filter alone to enforce a security boundary.

    TODO(auth): no ownership check yet, same caveat as /events above.
    TODO(pagination): capped at ORDERS_PAGE_SIZE results, no cursor
    pagination — fine for a normal day/location, not for very high volume.
    """
    shop, store = get_shop_and_store(location_id, db)
    access_token = await ensure_valid_token(store, db)

    now = datetime.utcnow()

    if date_from:
        range_start = date_from
    elif search:
        range_start = (now - timedelta(days=DEFAULT_SEARCH_LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    else:
        range_start = now.strftime("%Y-%m-%d")

    range_end = date_to if date_to else (now + timedelta(days=1)).strftime("%Y-%m-%d")

    filters = [
        f"location_id:{location_id}",
        f"created_at:>={range_start}",
        f"created_at:<={range_end}",
    ]

    if search:
        clean_search = sanitize_search_term(search)
        if clean_search:
            filters.append(f"name:#{clean_search}*")

    search_query = " AND ".join(filters)

    data = await shopify_graphql(
        store.shopify_shop_domain,
        access_token,
        ORDERS_QUERY,
        {"first": ORDERS_PAGE_SIZE, "query": search_query},
    )

    orders = [edge["node"] for edge in data.get("orders", {}).get("edges", [])]

    orders = [
        o for o in orders
        if o.get("physicalLocation")
        and str(o["physicalLocation"].get("legacyResourceId")) == location_id
    ]

    return [extract_order_fields_from_graphql(o) for o in orders]


# ── 5. GET /shopify/orders/{location_id}/{order_id} ─────────────────────────
ORDER_DETAIL_QUERY = """
query getOrder($id: ID!) {
  order(id: $id) {
    legacyResourceId
    name
    createdAt
    currencyCode
    totalPriceSet { shopMoney { amount currencyCode } }
    totalTaxSet { shopMoney { amount currencyCode } }
    taxLines { title rate priceSet { shopMoney { amount currencyCode } } }
    lineItems(first: 50) {
      edges {
        node {
          title
          quantity
          originalUnitPriceSet { shopMoney { amount currencyCode } }
          taxLines { title rate priceSet { shopMoney { amount currencyCode } } }
        }
      }
    }
    physicalLocation { legacyResourceId }
  }
}
"""


@router.get("/orders/{location_id}/{order_id}")
async def get_order_detail(location_id: str, order_id: str, db: Session = Depends(get_db)):
    """
    Full order detail for a single order — used by the tax-free refund UI
    when a specific transaction is opened. Confirms the order actually
    belongs to `location_id` before returning it, so one shop can't fetch
    another shop's order detail by guessing an order_id.

    Returns the same PII-minimized shape as the list endpoint (order,
    line items, tax, total) — not Shopify's raw order object. GraphQL
    requires explicit field selection, so unlike the old REST version this
    can no longer return "everything Shopify has" by default; if the
    refund UI needs specific additional fields, they should be added to
    ORDER_DETAIL_QUERY explicitly rather than exposing an unfiltered blob.

    TODO(auth): no ownership check yet, same caveat as /events above.
    """
    shop, store = get_shop_and_store(location_id, db)
    access_token = await ensure_valid_token(store, db)

    data = await shopify_graphql(
        store.shopify_shop_domain,
        access_token,
        ORDER_DETAIL_QUERY,
        {"id": to_gid("Order", order_id)},
    )

    order = data.get("order")
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order_location_id = (order.get("physicalLocation") or {}).get("legacyResourceId")
    if str(order_location_id) != location_id:
        raise HTTPException(status_code=403, detail="Order does not belong to this location")

    return extract_order_fields_from_graphql(order)


# ── 6. POST /shopify/link-shop-location ─────────────────────────────────────
@router.post("/link-shop-location")
async def link_shop_location(body: LinkShopLocationRequest, db: Session = Depends(get_db)):
    """
    Connects a Shop to one of its company's Shopify locations, so it starts
    receiving/streaming that location's live POS transactions. The
    company's Shopify store must already be connected via shopify.py's
    link-shopify-store — this only assigns which location within that
    store belongs to this shop.

    Rejects linking a location already claimed by a different Shop under
    the same Shopify store (409 conflict). To move a location, the frontend
    calls unlink-shop-location on the current owner first, then this
    endpoint — no implicit override here, so linking never has a silent
    side effect on another shop.

    Pure DB operation — no Shopify API call, unaffected by GraphQL migration.
    """
    shop = db.query(Shop).filter(Shop.id == body.shop_id).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found")

    store = db.query(ShopifyStore).filter(ShopifyStore.company_id == shop.company_id).first()
    if not store:
        raise HTTPException(status_code=400, detail="This shop's company has no connected Shopify store")

    conflict = db.query(Shop).filter(
        Shop.shopify_store_id == store.id,
        Shop.shopify_location_id == body.location_id,
        Shop.id != shop.id,
    ).first()
    if conflict:
        raise HTTPException(
            status_code=409,
            detail=f"This location is already connected to another shop (id={conflict.id})",
        )

    shop.shopify_store_id = store.id
    shop.shopify_location_id = body.location_id
    db.commit()

    return JSONResponse({"linked": True, "shop_id": shop.id, "location_id": body.location_id})


# ── 7. POST /shopify/unlink-shop-location ────────────────────────────────────
@router.post("/unlink-shop-location")
async def unlink_shop_location(body: UnlinkShopLocationRequest, db: Session = Depends(get_db)):
    """
    Disconnects a Shop from its Shopify location — clears shopify_store_id
    and shopify_location_id so it stops streaming transactions. Leaves the
    company's Shopify store connection itself untouched.

    Pure DB operation — no Shopify API call, unaffected by GraphQL migration.
    """
    shop = db.query(Shop).filter(Shop.id == body.shop_id).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found")

    shop.shopify_store_id = None
    shop.shopify_location_id = None
    db.commit()

    return JSONResponse({"unlinked": True, "shop_id": shop.id})