from datetime import datetime, timedelta
import base64
import hashlib
import hmac as hmac_lib
import logging
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Request, Depends, HTTPException
import httpx
import jwt
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Company, Shop, ShopifyStore
from app.services import crypto

router = APIRouter()
logger = logging.getLogger(__name__)


# ─── Request schemas ────────────────────────────────────────────────────────
class ExchangeTokenRequest(BaseModel):
    session_token: str | None = None


class LinkShopifyStoreRequest(BaseModel):
    shop_domain: str
    company_id: int


class UnlinkShopifyStoreRequest(BaseModel):
    shopify_store_id: int

class ShopOut(BaseModel):
    id: int
    name: str | None


class CompanyOut(BaseModel):
    id: int
    name: str
    shops: list[ShopOut]


# ─── HMAC / session-token verification ────────────────────────────────────────
def verify_hmac(query_params: dict) -> bool:
    """
    Checks that a request landing on our /shopify/app page really came from
    Shopify, and wasn't faked by someone else. Shopify signs every request
    with a hash (hmac) using our app's secret key — we recompute that same
    hash ourselves and compare it. If they match, the request is genuine.
    """
    params = {k: v for k, v in query_params.items() if k != "hmac"}
    received_hmac = query_params.get("hmac", "")

    sorted_params = urlencode(sorted(params.items()))
    computed_hmac = hmac_lib.new(
        settings.shopify_client_secret.encode(),
        sorted_params.encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac_lib.compare_digest(computed_hmac, received_hmac)


def verify_session_token(token: str) -> dict:
    """
    Checks that the session token our embedded page received from App Bridge
    is real and untampered. This token is how Shopify proves "this request
    is really coming from inside your app, loaded in our admin." We decode
    it using our client secret; if the signature doesn't match, it's rejected.
    """
    return jwt.decode(
        token,
        settings.shopify_client_secret,
        algorithms=["HS256"],
        audience=settings.shopify_client_id,
        leeway=60,  # allows for small clock differences between servers
    )


def verify_webhook_hmac(body: bytes, hmac_header: str) -> bool:
    """
    Same idea as verify_hmac above, but for webhooks instead of page loads.
    Shopify signs the raw webhook body and sends the signature in a header.
    We recompute it ourselves and compare, to make sure the webhook really
    came from Shopify and the data wasn't altered in transit.
    """
    if not hmac_header:
        return False
    digest = hmac_lib.new(
        settings.shopify_client_secret.encode(), body, hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode()
    return hmac_lib.compare_digest(computed_hmac, hmac_header)


def extract_shop_domain(claims: dict) -> str | None:
    """Return the Shopify shop host from verified session-token claims."""
    for claim_key in ("dest", "iss"):
        raw = claims.get(claim_key)
        if not isinstance(raw, str):
            continue

        host = (urlparse(raw).hostname or "").lower().strip()
        if host.endswith(".myshopify.com"):
            return host
    return None


# ─── Shopify Admin API — OAuth token exchange ──────────────────────────────────
async def exchange_token(shop_domain: str, session_token: str) -> dict:
    """
    Trades the short-lived session token for a real, longer-lived access
    token — the one we actually need to call Shopify's API (read orders,
    locations, etc.) on this store's behalf going forward. This hits
    Shopify's OAuth token endpoint directly — a separate concern from the
    Admin API, unaffected by the REST->GraphQL migration below.
    """
    url = f"https://{shop_domain}/admin/oauth/access_token"
    payload = {
        "client_id": settings.shopify_client_id,
        "client_secret": settings.shopify_client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": session_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "requested_token_type": "urn:shopify:params:oauth:token-type:offline-access-token",
        "expiring": "1",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload)
        resp.raise_for_status()
        return resp.json()


# ─── Shopify Admin API — GraphQL ────────────────────────────────────────────
# Duplicated here rather than shared with shopify_pos.py, matching this
# codebase's one-file-per-provider pattern (all helpers inline, no shared
# service module) — see square.py / smaregi.py for the same convention.
def raise_sanitized_shopify_error(exc: httpx.HTTPStatusError):
    """
    Logs Shopify's raw error response server-side (useful for debugging) but
    never forwards it verbatim to our own API clients — the raw body could
    contain internal Shopify details we don't want to expose. Status code is
    preserved since it's meaningful to the caller (404 vs 4xx vs 5xx).
    """
    logger.error(
        "[shopify api error] status=%s body=%s", exc.response.status_code, exc.response.text
    )
    raise HTTPException(status_code=exc.response.status_code, detail="Shopify API request failed")


async def shopify_graphql(
    shop_domain: str, access_token: str, query: str, variables: dict | None = None
) -> dict:
    """
    POSTs a query/mutation to Shopify's single GraphQL Admin API endpoint.
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


# ─── Webhook registration (called once, right after install) ──────────────────
WEBHOOK_SUBSCRIPTION_CREATE_MUTATION = """
mutation webhookSubscriptionCreate($topic: WebhookSubscriptionTopic!, $webhookSubscription: WebhookSubscriptionInput!) {
  webhookSubscriptionCreate(topic: $topic, webhookSubscription: $webhookSubscription) {
    webhookSubscription {
      id
      topic
      uri
    }
    userErrors {
      field
      message
    }
  }
}
"""


async def register_webhook(shop_domain: str, access_token: str, topic: str, address: str):
    """
    Tells Shopify: "please notify us at `address` whenever `topic` fires
    for this shop." Used for app/uninstalled (delivered to this backend)
    and orders/create + orders/paid (delivered to the POS backend).

    `topic` must be a GraphQL WebhookSubscriptionTopic enum value (e.g.
    "APP_UNINSTALLED", "ORDERS_CREATE") — not REST's old slash-separated
    strings like "app/uninstalled".

    GraphQL mutations report business-logic failures (like "this webhook
    is already registered") through a `userErrors` array in the response
    data, separately from shopify_graphql()'s generic error handling —
    that only catches HTTP-level and GraphQL-protocol-level failures.
    """
    data = await shopify_graphql(
        shop_domain,
        access_token,
        WEBHOOK_SUBSCRIPTION_CREATE_MUTATION,
        {
            "topic": topic,
            "webhookSubscription": {"uri": address, "format": "JSON"},
        },
    )

    result = data.get("webhookSubscriptionCreate") or {}
    user_errors = result.get("userErrors") or []

    if user_errors:
        # Already registered for this shop — not a real failure, same
        # no-op behavior the old REST version had for its 422
        # "already been taken" response.
        already_registered = any(
            "already" in err.get("message", "").lower() and "taken" in err.get("message", "").lower()
            for err in user_errors
        )
        if already_registered:
            return

        logger.error("[webhook registration error] topic=%s errors=%s", topic, user_errors)
        raise HTTPException(status_code=502, detail="Failed to register Shopify webhook")

    return result.get("webhookSubscription")


async def register_all_webhooks(shop_domain: str, access_token: str):
    """
    Registers every webhook this app needs: uninstall (handled by this
    backend) and order events (handled by the POS backend for the live
    transaction stream).
    """
    await register_webhook(
        shop_domain, access_token, "APP_UNINSTALLED",
        f"{settings.app_base_url}/shopify/webhooks/app/uninstalled",
    )
    await register_webhook(
        shop_domain, access_token, "ORDERS_CREATE",
        f"{settings.pos_backend_url}/shopify/webhook",
    )
    await register_webhook(
        shop_domain, access_token, "ORDERS_PAID",
        f"{settings.pos_backend_url}/shopify/webhook",
    )


# ─── Routes ─────────────────────────────────────────────────────────────────
@router.get("/shopify/app", response_class=HTMLResponse)
async def shopify_app(request: Request):
    """
    The page Shopify loads inside its admin iframe after a merchant installs
    or opens the app. Checks the request really came from Shopify, silently
    exchanges the session token for a real access token, then shows our
    dashboard login (also iframed) once that succeeds.
    """
    params = dict(request.query_params)

    if not verify_hmac(params):
        raise HTTPException(status_code=400, detail="Invalid hmac")

    shop_domain = params.get("shop", "").lower().strip()
    if not shop_domain.endswith(".myshopify.com"):
        raise HTTPException(status_code=400, detail="Invalid shop")

    dashboard_url = f"https://staging.dashboard.samurai-tax.com/login"
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta name="shopify-api-key" content="{settings.shopify_client_id}" />
    <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
    <style>
        html, body {{ margin: 0; padding: 0; height: 100%; }}
        .loading-wrap {{
            position: fixed;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #fff;
            z-index: 10;
        }}
        .spinner {{
            width: 44px;
            height: 44px;
            border: 4px solid #e5e7eb;
            border-top-color: #164d86;
            border-radius: 50%;
            animation: spin 0.9s linear infinite;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        iframe {{ width: 100%; height: 100vh; border: none; display: none; }}
    </style>
    </head>
    <body>
    <div id="loading" class="loading-wrap">
        <div class="spinner"></div>
    </div>
    <iframe id="dashboard"></iframe>

        <script>
            async function connect() {{
            try {{
                const sessionToken = await window.shopify.idToken();

                const res = await fetch('/shopify/auth/token', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + sessionToken
                }},
                body: JSON.stringify({{ session_token: sessionToken }})
                }});

                const data = await res.json();

                if (data.connected) {{
                document.getElementById('loading').style.display = 'none';
                const iframe = document.getElementById('dashboard');
                iframe.src = '{dashboard_url}';
                iframe.style.display = 'block';
                }} else {{
                document.getElementById('loading').innerText = 'Connection failed';
                }}
            }} catch (err) {{
                document.getElementById('loading').innerText = 'Connection failed: ' + err.message;
            }}
            }}
        connect();
    </script>
    </body>
    </html>
    """
    return HTMLResponse(
        content=html,
        headers={
            "Content-Security-Policy": (
                f"frame-ancestors https://{shop_domain} https://admin.shopify.com;"
            )
        },
    )


@router.post("/shopify/auth/token")
async def exchange(
    request: Request,
    body: ExchangeTokenRequest | None = None,
    db: Session = Depends(get_db),
):
    """
    Takes the session token sent from our embedded page, verifies it's real,
    trades it for a proper Shopify access token, and saves that (encrypted)
    to our database. Also registers the uninstall + order webhooks for this
    shop, so we're notified later if they remove the app or make a POS sale.

    Accepts the token via Authorization header (preferred) or JSON body,
    matching what the /shopify/app page actually sends.
    """
    authorization = request.headers.get("Authorization", "")
    session_token = authorization.removeprefix("Bearer ").strip()
    if not session_token and body is not None:
        session_token = body.session_token

    if not session_token:
        raise HTTPException(status_code=400, detail="Missing session_token")

    try:
        claims = verify_session_token(session_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session token")

    shop_domain = extract_shop_domain(claims)
    if not shop_domain:
        raise HTTPException(status_code=400, detail="Invalid token claims")

    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_shop_domain == shop_domain
    ).first()
    if (
        store
        and store.shopify_access_token_encrypted
        and store.disconnected_at is None
        and (
            store.access_token_expires_at is None
            or store.access_token_expires_at > datetime.utcnow() + timedelta(seconds=60)
        )
    ):
        return JSONResponse({"connected": True})

    try:
        token_data = await exchange_token(shop_domain, session_token)
    except Exception:
        logger.exception("Shopify token exchange failed for shop %s", shop_domain)
        raise HTTPException(status_code=502, detail="Unable to connect to Shopify")

    access_token = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    refresh_expires_in = token_data.get("refresh_token_expires_in")
    scopes = token_data.get("scope", "")

    if not store:
        store = ShopifyStore(shopify_shop_domain=shop_domain)
        db.add(store)

    store.shopify_access_token_encrypted = crypto.encrypt(access_token)
    store.shopify_refresh_token_encrypted = crypto.encrypt(refresh_token) if refresh_token else None
    store.scopes = scopes
    store.access_token_expires_at = (
        datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None
    )
    store.refresh_token_expires_at = (
        datetime.utcnow() + timedelta(seconds=refresh_expires_in) if refresh_expires_in else None
    )
    store.connected_at = datetime.utcnow()
    store.disconnected_at = None

    db.commit()

    try:
        await register_all_webhooks(shop_domain, access_token)
    except Exception:
        # The connection is usable, but this needs an operational retry.
        logger.exception("Webhook registration failed for shop %s", shop_domain)

    return JSONResponse({"connected": True})


@router.get("/shopify/companies", response_model=list[CompanyOut])
def get_companies(db: Session = Depends(get_db)):
    companies = db.query(Company).order_by(Company.id).all()
    return [
        CompanyOut(
            id=c.id,
            name=c.name,
            shops=[ShopOut(id=s.id, name=s.name) for s in c.shops],
        )
        for c in companies
    ]

@router.post("/shopify/link-shopify-store")
async def link_shopify_store(body: LinkShopifyStoreRequest, db: Session = Depends(get_db)):
    """
    Links a Shopify store to a SAMURAI TAX company account, once a merchant
    has successfully logged in. Called by our dashboard after login succeeds.

    Rejects overwriting an existing link to a *different* company (409) so
    a stale/duplicate dashboard request can't silently steal a store away
    from another company. Re-linking the same company is a no-op success.
    """
    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_shop_domain == body.shop_domain
    ).first()
    if not store:
        raise HTTPException(status_code=404, detail="Shop not found — install app first")

    company = db.query(Company).filter(Company.id == body.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    if store.company_id is not None and store.company_id != company.id:
        raise HTTPException(
            status_code=409,
            detail="Shopify store is already linked to a different company",
        )

    store.company_id = company.id
    db.commit()

    return JSONResponse({"linked": True, "company_id": company.id})


@router.post("/shopify/unlink-shopify-store")
async def unlink_shopify_store(body: UnlinkShopifyStoreRequest, db: Session = Depends(get_db)):
    """
    Disconnects a Shopify store from its Company (company/store card's
    連携解除 button). Also clears any shops still pointing at this store,
    since a shop can't stay linked to a location on a store that's no
    longer linked to its company.
    """
    store = db.query(ShopifyStore).filter(ShopifyStore.id == body.shopify_store_id).first()
    if not store:
        raise HTTPException(status_code=404, detail="Shopify store not found")

    db.query(Shop).filter(Shop.shopify_store_id == store.id).update(
        {"shopify_store_id": None, "shopify_location_id": None}
    )

    store.company_id = None
    db.commit()

    return JSONResponse({"unlinked": True})


@router.get("/shopify/stores/available-to-connect")
async def get_available_to_connect_stores(db: Session = Depends(get_db)):
    """
    Returns Shopify stores that have completed OAuth install but aren't
    yet linked to a Company. Used to populate the "pick a company"
    suggestion dropdown on the connect page (Page 1, step 1).
    """
    stores = db.query(ShopifyStore).filter(
        ShopifyStore.company_id.is_(None),
        ShopifyStore.disconnected_at.is_(None),
    ).all()

    return [
        {
            "id": store.id,
            "shopify_shop_domain": store.shopify_shop_domain,
            "connected_at": store.connected_at,
        }
        for store in stores
    ]


@router.post("/shopify/webhooks/app/uninstalled")
async def app_uninstalled(request: Request, db: Session = Depends(get_db)):
    """
    Shopify calls this the moment a merchant uninstalls the app. We verify
    the request is genuinely from Shopify, then clear the now-dead access
    token from our database so we don't keep trying to use it.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_webhook_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    shop_domain = request.headers.get("X-Shopify-Shop-Domain")

    try:
        store = db.query(ShopifyStore).filter(
            ShopifyStore.shopify_shop_domain == shop_domain
        ).first()
        if store:
            store.shopify_access_token_encrypted = None
            store.shopify_refresh_token_encrypted = None
            store.disconnected_at = datetime.utcnow()
            db.commit()
    except Exception:
        logger.exception("Failed to process app/uninstalled for shop %s", shop_domain)

    return JSONResponse({"received": True})


@router.post("/shopify/webhooks/compliance")
async def compliance_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handles all three mandatory GDPR/CCPA compliance webhooks in one place:
    customers/data_request, customers/redact, and shop/redact. Shopify tells
    us which one this is via the X-Shopify-Topic header.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not verify_webhook_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    topic = request.headers.get("X-Shopify-Topic", "")
    shop_domain = request.headers.get("X-Shopify-Shop-Domain")

    try:
        if topic == "customers/data_request":
            logger.info("[compliance] data request for shop=%s", shop_domain)

        elif topic == "customers/redact":
            logger.info("[compliance] customer redact for shop=%s", shop_domain)

        elif topic == "shop/redact":
            store = db.query(ShopifyStore).filter(
                ShopifyStore.shopify_shop_domain == shop_domain
            ).first()
            if store:
                db.query(Shop).filter(Shop.shopify_store_id == store.id).update(
                    {"shopify_store_id": None, "shopify_location_id": None}
                )
                db.delete(store)
                db.commit()
            logger.info("[compliance] shop redact completed for shop=%s", shop_domain)
    except Exception:
        logger.exception("Failed to process compliance webhook topic=%s shop=%s", topic, shop_domain)

    return JSONResponse({"received": True})


@router.get("/health")
async def health():
    """Basic liveness check — no DB or auth dependency."""
    return JSONResponse({"status": "ok"})