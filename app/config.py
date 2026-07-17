from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    shopify_client_id: str
    shopify_client_secret: str
    shopify_api_version: str = "2026-04"
    token_encryption_key: str
    database_url: str
    app_base_url: str

    class Config:
        env_file = ".env"


settings = Settings()