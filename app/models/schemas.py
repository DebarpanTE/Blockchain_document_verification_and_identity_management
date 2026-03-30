"""Pydantic request/response schemas."""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from enum import Enum


class DocType(str, Enum):
    PASSPORT = "passport"
    NATIONAL_ID = "national_id"
    DRIVER_LICENSE = "driver_license"
    BIRTH_CERTIFICATE = "birth_certificate"
    TAX_ID = "tax_id"


# ── Auth ────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=128)
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    is_verified: bool
    is_active: bool
    created_at: float
    public_key: str

    class Config:
        from_attributes = True


# ── Identity Documents ───────────────────────────────────────────────
class IdentityDocCreate(BaseModel):
    doc_type: DocType
    fields: Dict[str, str] = Field(..., description="Document fields to hash and store")


class IdentityDocOut(BaseModel):
    id: Optional[str]
    doc_type: Optional[str]
    doc_hash: Optional[str]
    is_verified: bool
    is_revoked: bool
    tx_id: Optional[str]
    block_index: Optional[int]
    created_at: Optional[float]   # ← was float, change to Optional[float]
    metadata: Dict[str, Any] = {}

    class Config:
        from_attributes = True

class VerifyDocRequest(BaseModel):
    doc_id: str
    fields: Dict[str, str] = Field(..., description="Original fields to verify against hash")


class VerifyDocResponse(BaseModel):
    doc_id: str
    is_valid: bool
    signature_valid: bool
    chain_valid: bool
    message: str


# ── Access Grants ────────────────────────────────────────────────────
class AccessGrantCreate(BaseModel):
    document_id: str
    grantee_identifier: str = Field(..., description="Email or username of recipient")
    fields_allowed: List[str] = Field(..., description="Which fields to expose")
    expires_hours: Optional[int] = Field(None, description="Expiry in hours; None = no expiry")


class AccessGrantOut(BaseModel):
    id: str
    grantee_identifier: str
    document_id: str
    fields_allowed: List[str]
    expires_at: Optional[float]
    is_active: bool
    tx_id: Optional[str]
    created_at: Optional[float]

    class Config:
        from_attributes = True


# ── Blockchain ───────────────────────────────────────────────────────
class BlockOut(BaseModel):
    index: int
    hash: str
    previous_hash: str
    timestamp: float
    nonce: int
    transaction_count: int


class ChainStatsOut(BaseModel):
    total_blocks: int
    total_transactions: int
    is_valid: bool
    pending_transactions: int
    difficulty: int