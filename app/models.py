from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship

from app.db import Base


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    shopify_stores = relationship("ShopifyStore", back_populates="company")
    shops = relationship("Shop", back_populates="company")


class ShopifyStore(Base):
    __tablename__ = "shopify_stores"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True, index=True)

    shopify_shop_domain = Column(String, unique=True, nullable=False)
    shopify_access_token_encrypted = Column(String, nullable=True)
    shopify_refresh_token_encrypted = Column(String, nullable=True)
    scopes = Column(String, nullable=True)
    access_token_expires_at = Column(DateTime, nullable=True)
    refresh_token_expires_at = Column(DateTime, nullable=True)
    connected_at = Column(DateTime, nullable=True)
    disconnected_at = Column(DateTime, nullable=True)

    company = relationship("Company", back_populates="shopify_stores")
    shops = relationship("Shop", back_populates="shopify_store")


class Shop(Base):
    __tablename__ = "shops"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    shopify_store_id = Column(Integer, ForeignKey("shopify_stores.id"), nullable=True)

    name = Column(String, nullable=True)
    shopify_location_id = Column(String, nullable=True)

    company = relationship("Company", back_populates="shops")
    shopify_store = relationship("ShopifyStore", back_populates="shops")