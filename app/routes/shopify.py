from datetime import datetime, timedelta
import logging
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Request, Depends, HTTPException
import jwt
import hmac as hmac_lib
import hashlib
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Company, ShopifyStore, ShopifyLead
from app.services import shopify_auth, crypto

router = APIRouter()
logger = logging.getLogger(__name__)


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

@router.get("/shopify/app", response_class=HTMLResponse)
async def shopify_app(request: Request):
    """
    The page Shopify loads inside its admin iframe after a merchant installs
    or opens the app. Checks the request really came from Shopify, silently
    exchanges the session token for a real access token, then shows our
    dashboard login (also iframed) once that succeeds.
    """
    # Params are passed from Shopify to our app, including the HMAC signature.
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
async def exchange(request: Request, db: Session = Depends(get_db)):
    """
    Takes the session token sent from our embedded page, verifies it's real,
    trades it for a proper Shopify access token, and saves that (encrypted)
    to our database. Also registers the uninstall webhook for this shop,
    so we're notified later if they ever remove the app.
    """

    # App Bridge sends the session token in Authorization. Retain the JSON-body
    # fallback for existing clients during the transition.
    authorization = request.headers.get("Authorization", "")
    session_token = authorization.removeprefix("Bearer ").strip()
    if not session_token:
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        session_token = body.get("session_token") if isinstance(body, dict) else None

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
        and store.access_token
        and store.uninstalled_at is None
        and (
            store.access_expires_at is None
            or store.access_expires_at > datetime.utcnow() + timedelta(seconds=60)
        )
    ):
        return JSONResponse({"connected": True})

    try:
        token_data = await shopify_auth.exchange_token(shop_domain, session_token)
    except Exception:
        logger.exception("Shopify token exchange failed for shop %s", shop_domain)
        raise HTTPException(status_code=502, detail="Unable to connect to Shopify")

    access_token = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    scopes = token_data.get("scope", "")

    if not store:
        store = ShopifyStore(shopify_shop_domain=shop_domain)
        db.add(store)

    store.access_token = crypto.encrypt(access_token)
    store.refresh_token = crypto.encrypt(refresh_token) if refresh_token else None
    store.scopes = scopes
    store.access_expires_at = (
        datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None
    )
    store.uninstalled_at = None

    db.commit()

    try:
        await shopify_auth.register_uninstall_webhook(shop_domain, access_token)
    except Exception:
        # The connection is usable, but this needs an operational retry.
        logger.exception("Uninstall webhook registration failed for shop %s", shop_domain)

    return JSONResponse({"connected": True})


@router.post("/shopify/contact-request")
async def contact_request(request: Request, db: Session = Depends(get_db)):
    """
    Called when a merchant without a SAMURAI TAX account clicks "Contact us."
    Saves their shop domain as a lead for our sales team to follow up on,
    then returns the URL to redirect them to.
    """
    body = await request.json()
    shop_domain = body.get("shop_domain")

    if not shop_domain:
        raise HTTPException(status_code=400, detail="Missing shop_domain")

    lead = db.query(ShopifyLead).filter(ShopifyLead.shop_domain == shop_domain).first()
    if not lead:
        lead = ShopifyLead(shop_domain=shop_domain)
        db.add(lead)
        db.commit()

    contact_url = f"https://tai-matsu.jp/contact?shop={shop_domain}"
    return JSONResponse({"contact_url": contact_url})


@router.post("/shopify/link-shop")
async def link_shop(request: Request, db: Session = Depends(get_db)):
    """
    Links a Shopify store to a SAMURAI TAX company account, once a merchant
    has successfully logged in. Called by our dashboard after login succeeds.
    """
    body = await request.json()
    shop_domain = body.get("shop_domain")
    company_id = body.get("company_id")

    if not shop_domain or not company_id:
        raise HTTPException(status_code=400, detail="Missing shop_domain or company_id")

    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_shop_domain == shop_domain
    ).first()
    if not store:
        raise HTTPException(status_code=404, detail="Shop not found — install app first")

    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    store.company_id = company.id
    db.commit()

    return JSONResponse({"linked": True, "company_id": company.id})


@router.post("/shopify/webhooks/app/uninstalled")
async def app_uninstalled(request: Request, db: Session = Depends(get_db)):
    """
    Shopify calls this the moment a merchant uninstalls the app. We verify
    the request is genuinely from Shopify, then clear the now-dead access
    token from our database so we don't keep trying to use it.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not shopify_auth.verify_webhook_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    shop_domain = request.headers.get("X-Shopify-Shop-Domain")

    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_shop_domain == shop_domain
    ).first()
    if store:
        store.access_token = None
        store.refresh_token = None
        store.uninstalled_at = datetime.utcnow()
        db.commit()

    return JSONResponse({"received": True})


"""
    GDPR compliance webhooks. Shopify requires apps to implement three webhooks
    to comply with privacy laws like GDPR and CCPA. These are:
    - customers/data_request: A customer has requested to see their personal data.
    - customers/redact: A customer has requested to delete their personal data.
    - shop/redact: The shop has uninstalled the app and requests all data be deleted
    We handle all three in one endpoint, since the payloads are similar and
    Shopify tells us which one it is via the X-Shopify-Topic header.
"""
@router.post("/shopify/webhooks/compliance")
async def compliance_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handles all three mandatory GDPR/CCPA compliance webhooks in one place:
    customers/data_request, customers/redact, and shop/redact. Shopify tells
    us which one this is via the X-Shopify-Topic header.
    """
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")

    if not shopify_auth.verify_webhook_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    topic = request.headers.get("X-Shopify-Topic", "")
    shop_domain = request.headers.get("X-Shopify-Shop-Domain")
    payload = await request.json()

    if topic == "customers/data_request":
        # A customer asked to see their data. We don't currently store
        # customer-level personal data ourselves, so there's nothing to
        # gather here — but Shopify still requires we acknowledge this.
        print(f"[compliance] data request for shop={shop_domain}, payload={payload}")

    elif topic == "customers/redact":
        # A customer asked to delete their data. Same situation — nothing
        # customer-specific stored in this sandbox yet.
        print(f"[compliance] customer redact for shop={shop_domain}, payload={payload}")

    elif topic == "shop/redact":
        # Fires 48 hours after uninstall. This is where we permanently
        # erase everything we stored for this shop.
        store = db.query(ShopifyStore).filter(
            ShopifyStore.shopify_shop_domain == shop_domain
        ).first()
        if store:
            db.delete(store)
            db.commit()
        print(f"[compliance] shop redact completed for shop={shop_domain}")

    return JSONResponse({"received": True})
