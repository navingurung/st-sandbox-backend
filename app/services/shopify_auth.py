import base64
import hashlib
import hmac as hmac_lib
from urllib.parse import urlencode

import httpx
import jwt

from app.config import settings


# def verify_hmac(query_params: dict) -> bool:
#     """
#     Checks that a request landing on our /shopify/app page really came from
#     Shopify, and wasn't faked by someone else. Shopify signs every request
#     with a hash (hmac) using our app's secret key — we recompute that same
#     hash ourselves and compare it. If they match, the request is genuine.
#     """
#     params = {k: v for k, v in query_params.items() if k != "hmac"}
#     received_hmac = query_params.get("hmac", "")

#     sorted_params = urlencode(sorted(params.items()))
#     computed_hmac = hmac_lib.new(
#         settings.shopify_client_secret.encode(),
#         sorted_params.encode(),
#         hashlib.sha256,
#     ).hexdigest()

#     return hmac_lib.compare_digest(computed_hmac, received_hmac)


# def verify_session_token(token: str) -> dict:
#     """
#     Checks that the session token our embedded page received from App Bridge
#     is real and untampered. This token is how Shopify proves "this request
#     is really coming from inside your app, loaded in our admin." We decode
#     it using our client secret; if the signature doesn't match, it's rejected.
#     """
#     return jwt.decode(
#         token,
#         settings.shopify_client_secret,
#         algorithms=["HS256"],
#         audience=settings.shopify_client_id,
#         leeway=60,  # allows for small clock differences between servers
#     )


async def exchange_token(shop_domain: str, session_token: str) -> dict:
    """
    Trades the short-lived session token for a real, longer-lived access
    token — the one we actually need to call Shopify's API (read orders,
    locations, etc.) on this store's behalf going forward.
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


async def refresh_access_token(shop_domain: str, refresh_token: str) -> dict:
    """
    Trades a refresh token for a brand new access token + refresh token pair,
    used when the current access token is close to expiring (~60 min lifetime).
    """
    url = f"https://{shop_domain}/admin/oauth/access_token"
    payload = {
        "client_id": settings.shopify_client_id,
        "client_secret": settings.shopify_client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload)
        resp.raise_for_status()
        return resp.json()


def verify_webhook_hmac(body: bytes, hmac_header: str) -> bool:
    """
    Same idea as verify_hmac above, but for webhooks instead of page loads.
    Shopify signs the raw webhook body and sends the signature in a header.
    We recompute it ourselves and compare, to make sure the webhook really
    came from Shopify and the data wasn't altered in transit.
    """
    digest = hmac_lib.new(
        settings.shopify_client_secret.encode(), body, hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest).decode()
    return hmac_lib.compare_digest(computed_hmac, hmac_header)


async def register_uninstall_webhook(shop_domain: str, access_token: str):
    """
    Tells Shopify: "please notify our backend if this store ever uninstalls
    the app." We call this once, right after a successful install, so that
    later — if the merchant uninstalls — we get a webhook telling us to
    clear their stored access token from our database.
    """
    url = f"https://{shop_domain}/admin/api/{settings.shopify_api_version}/webhooks.json"
    headers = {"X-Shopify-Access-Token": access_token, "Content-Type": "application/json"}
    payload = {
        "webhook": {
            "topic": "app/uninstalled",
            "address": f"{settings.app_base_url}/shopify/webhooks/app/uninstalled",
            "format": "json",
        }
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code == 422 and "already been taken" in resp.text:
            return  # webhook already registered for this shop — nothing more to do
        if resp.status_code >= 400:
            print(f"[webhook registration error body] {resp.text}")
        resp.raise_for_status()
        return resp.json()