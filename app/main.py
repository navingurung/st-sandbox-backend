import os

from fastapi import FastAPI

from app.db import Base, engine
from app.routes import shopify, shopify_pos
from fastapi.middleware.cors import CORSMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(title="st-sandbox")

app.include_router(shopify.router)
app.include_router(shopify_pos.router)

FRONTEND_URL = os.getenv("FRONTEND_URL")
DASHBOARD_URL = os.getenv("DASHBOARD_URL")
origins = [url for url in [FRONTEND_URL, DASHBOARD_URL] if url]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "Access-Control-Allow-Origin"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

