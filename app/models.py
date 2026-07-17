from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship

from app.db import Base


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    shopify_stores = relationship("ShopifyStore", back_populates="company")


class ShopifyStore(Base):
    __tablename__ = "shopify_stores"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)

    shopify_shop_domain = Column(String, unique=True, index=True, nullable=False)
    access_token = Column(String, nullable=True)      # Fernet-encrypted
    refresh_token = Column(String, nullable=True)     # Fernet-encrypted
    scopes = Column(String, nullable=True)
    access_expires_at = Column(DateTime, nullable=True)

    connected_at = Column(DateTime, server_default=func.now())
    uninstalled_at = Column(DateTime, nullable=True)

    company = relationship("Company", back_populates="shopify_stores")
    shops = relationship("Shop", back_populates="shopify_store")


class Shop(Base):
    __tablename__ = "shops"

    id = Column(Integer, primary_key=True, index=True)
    shopify_store_id = Column(Integer, ForeignKey("shopify_stores.id"), nullable=True)

    name = Column(String, nullable=True)
    use_shopify = Column(Boolean, default=False)
    shopify_location_id = Column(String, nullable=True)

    shopify_store = relationship("ShopifyStore", back_populates="shops")


class ShopifyLead(Base):
    __tablename__ = "shopify_leads"

    id = Column(Integer, primary_key=True, index=True)
    shop_domain = Column(String, unique=True, index=True, nullable=False)
    requested_at = Column(DateTime, server_default=func.now())
    contacted = Column(Boolean, default=False)