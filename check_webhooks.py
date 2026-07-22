import asyncio
import httpx
from app.config import settings
from app.db import SessionLocal
from app.models import ShopifyStore
from app.services import crypto

QUERY = """
{
  webhookSubscriptions(first: 20) {
    edges {
      node {
        topic
        endpoint {
          __typename
          ... on WebhookHttpEndpoint { callbackUrl }
        }
      }
    }
  }
}
"""

async def main():
    db = SessionLocal()
    store = db.query(ShopifyStore).filter(
        ShopifyStore.shopify_access_token_encrypted.isnot(None)
    ).first()
    token = crypto.decrypt(store.shopify_access_token_encrypted)
    url = f"https://{store.shopify_shop_domain}/admin/api/{settings.shopify_api_version}/graphql.json"

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            headers={"X-Shopify-Access-Token": token, "Content-Type": "application/json"},
            json={"query": QUERY},
        )
    print(resp.json())

asyncio.run(main())