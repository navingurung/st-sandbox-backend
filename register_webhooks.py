import asyncio

from app.db import SessionLocal
from app.models import ShopifyStore
from app.services import crypto
from app.routes.shopify import register_all_webhooks


async def main():
    db = SessionLocal()
    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_access_token_encrypted.isnot(None)
    ).first()

    if not store:
        print("No connected store found in DB")
        return

    token = crypto.decrypt(store.shopify_access_token_encrypted)
    print(f"Registering webhooks for {store.shopify_shop_domain} ...")

    try:
        await register_all_webhooks(store.shopify_shop_domain, token)
        print("register_all_webhooks completed without raising.")
    except Exception as exc:
        print(f"register_all_webhooks raised: {exc!r}")


asyncio.run(main())