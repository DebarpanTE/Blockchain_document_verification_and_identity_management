"""Identity document endpoints."""
import uuid
import time
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.database import get_db, User, IdentityDocument
from app.models.schemas import IdentityDocCreate, IdentityDocOut, VerifyDocRequest, VerifyDocResponse
from app.services.auth import get_current_user
from app.services.blockchain import (
    get_blockchain, Transaction, KeyManager, hash_fields
)

router = APIRouter(prefix="/api/identity", tags=["Identity Documents"])


@router.post("/documents", response_model=IdentityDocOut, status_code=201)
async def register_document(
    data: IdentityDocCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Hash identity fields and register on-chain."""
    doc_hash = hash_fields(data.fields)

    existing = await db.execute(select(IdentityDocument).where(IdentityDocument.doc_hash == doc_hash))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Document with identical content already registered")

    bc = get_blockchain()
    tx_id = str(uuid.uuid4())

    tx = Transaction(
        tx_id=tx_id,
        user_id=str(getattr(current_user, "id", "")),
        action="REGISTER",
        document_hash=doc_hash,
        metadata={
            "doc_type": data.doc_type.value,
            "owner": str(getattr(current_user, "username", "")),
        },
        timestamp=time.time(),
    )

    tx.signature = KeyManager.sign(
        tx.signing_payload(),
        str(getattr(current_user, "private_key_encrypted", ""))
    )
    bc.add_transaction(tx)
    block = bc.mine_block()

    doc = IdentityDocument(
        id=str(uuid.uuid4()),
        owner_id=getattr(current_user, "id", ""),
        doc_type=data.doc_type.value,
        doc_hash=doc_hash,
        metadata_json=json.dumps({"doc_type": data.doc_type.value, "field_count": len(data.fields)}),
        tx_id=tx_id,
        block_index=block.index if block else None,
        created_at=time.time(),
        updated_at=time.time(),
    )
    db.add(doc)
    await db.commit()
    await db.refresh(doc)

    return _to_out(doc)


@router.get("/documents", response_model=list[IdentityDocOut])
async def list_documents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(IdentityDocument).where(
            IdentityDocument.owner_id == getattr(current_user, "id", "")
        )
    )
    docs = result.scalars().all()
    return [_to_out(d) for d in docs]


@router.get("/documents/{doc_id}", response_model=IdentityDocOut)
async def get_document(
    doc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = await _get_owned_doc(doc_id, str(getattr(current_user, "id", "")), db)
    return _to_out(doc)


@router.post("/verify", response_model=VerifyDocResponse)
async def verify_document(
    req: VerifyDocRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify that submitted fields match the on-chain hash."""
    doc = await _get_owned_doc(req.doc_id, str(getattr(current_user, "id", "")), db)

    recomputed_hash = hash_fields(req.fields)
    hash_match = recomputed_hash == getattr(doc, "doc_hash", "")

    bc = get_blockchain()
    doc_tx_id = getattr(doc, "tx_id", None)
    chain_tx = bc.find_transaction(str(doc_tx_id)) if doc_tx_id else None
    chain_valid = chain_tx is not None and chain_tx["document_hash"] == getattr(doc, "doc_hash", "")

    sig_valid = False
    if chain_tx and chain_tx.get("signature"):
        payload = json.dumps({
            "tx_id": chain_tx["tx_id"],
            "user_id": chain_tx["user_id"],
            "action": chain_tx["action"],
            "document_hash": chain_tx["document_hash"],
            "metadata": chain_tx["metadata"],
            "timestamp": chain_tx["timestamp"],
        }, sort_keys=True)
        sig_valid = KeyManager.verify(
            payload,
            chain_tx["signature"],
            str(getattr(current_user, "public_key", ""))
        )

    is_valid = hash_match and chain_valid
    return VerifyDocResponse(
        doc_id=req.doc_id,
        is_valid=is_valid,
        signature_valid=sig_valid,
        chain_valid=chain_valid,
        message="✓ Document verified on-chain" if is_valid else "✗ Verification failed",
    )


@router.delete("/documents/{doc_id}")
async def revoke_document(
    doc_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _get_owned_doc(doc_id, str(getattr(current_user, "id", "")), db)

    await db.execute(
        update(IdentityDocument).where(IdentityDocument.id == doc_id).values(
            is_revoked=True,
            updated_at=time.time()
        )
    )

    bc = get_blockchain()
    doc_res = await db.execute(select(IdentityDocument).where(IdentityDocument.id == doc_id))
    doc = doc_res.scalar_one_or_none()

    tx = Transaction(
        tx_id=str(uuid.uuid4()),
        user_id=str(getattr(current_user, "id", "")),
        action="REVOKE",
        document_hash=str(getattr(doc, "doc_hash", "")) if doc else "",
        metadata={"doc_id": doc_id},
        timestamp=time.time(),
    )
    tx.signature = KeyManager.sign(
        tx.signing_payload(),
        str(getattr(current_user, "private_key_encrypted", ""))
    )
    bc.add_transaction(tx)
    bc.mine_block()

    await db.commit()
    return {"message": "Document revoked successfully"}


# ── Helpers ──────────────────────────────────────────────────────────
async def _get_owned_doc(doc_id: str, owner_id: str, db: AsyncSession) -> IdentityDocument:
    result = await db.execute(
        select(IdentityDocument).where(
            IdentityDocument.id == doc_id,
            IdentityDocument.owner_id == owner_id,
        )
    )
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


def _to_out(doc: IdentityDocument) -> IdentityDocOut:
    meta = {}
    try:
        meta = json.loads(str(getattr(doc, "metadata_json", "{}")))
    except Exception:
        pass
    return IdentityDocOut(
        id=str(getattr(doc, "id", "")),
        doc_type=str(getattr(doc, "doc_type", "")),
        doc_hash=str(getattr(doc, "doc_hash", "")),
        is_verified=bool(getattr(doc, "is_verified", False)),
        is_revoked=bool(getattr(doc, "is_revoked", False)),
        tx_id=str(getattr(doc, "tx_id")) if getattr(doc, "tx_id", None) else None,
        block_index=int(getattr(doc, "block_index")) if getattr(doc, "block_index", None) is not None else None,
        created_at=float(getattr(doc, "created_at")) if getattr(doc, "created_at", None) else None,
        metadata=meta,
    )