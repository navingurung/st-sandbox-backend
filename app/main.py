from fastapi import FastAPI

from app.db import Base, engine
from app.routes import shopify

Base.metadata.create_all(bind=engine)

app = FastAPI(title="st-sandbox")

app.include_router(shopify.router)


@app.get("/health")
def health():
    return {"status": "ok"}