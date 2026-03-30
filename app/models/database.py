"""SQLAlchemy ORM models."""
from sqlalchemy import Column, String, Boolean, Float, Text, ForeignKey, Integer
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from config import get_settings

settings = get_settings()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False, index=True)
    full_name = Column(String(256), nullable=False)
    hashed_password = Column(String(256), nullable=False)
    public_key = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False)  # Stored encrypted in prod
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(Float, nullable=False)

    identity_docs = relationship("IdentityDocument", back_populates="owner", cascade="all, delete")
    access_grants = relationship("AccessGrant", back_populates="grantor", foreign_keys="AccessGrant.grantor_id", cascade="all, delete")


class IdentityDocument(Base):
    __tablename__ = "identity_documents"

    id = Column(String(36), primary_key=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    doc_type = Column(String(64), nullable=False)   # passport, national_id, driver_license
    doc_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 on-chain hash
    metadata_json = Column(Text, nullable=False)   # Non-sensitive metadata only
    is_verified = Column(Boolean, default=False)
    is_revoked = Column(Boolean, default=False)
    tx_id = Column(String(36), nullable=True)      # Blockchain transaction ID
    block_index = Column(Integer, nullable=True)
    created_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=False)

    owner = relationship("User", back_populates="identity_docs")
    access_grants = relationship("AccessGrant", back_populates="document", cascade="all, delete")


class AccessGrant(Base):
    __tablename__ = "access_grants"

    id = Column(String(36), primary_key=True)
    grantor_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    grantee_identifier = Column(String(256), nullable=False)  # Email or username of recipient
    document_id = Column(String(36), ForeignKey("identity_documents.id"), nullable=False)
    fields_allowed = Column(Text, nullable=False)  # JSON list of allowed fields
    expires_at = Column(Float, nullable=True)
    is_active = Column(Boolean, default=True)
    tx_id = Column(String(36), nullable=True)
    created_at = Column(Float, nullable=False)

    grantor = relationship("User", back_populates="access_grants", foreign_keys=[grantor_id])
    document = relationship("IdentityDocument", back_populates="access_grants")


# DB Engine + Session
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()