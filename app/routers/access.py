"""Access grant management endpoints."""
import uuid
import time
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.database import get_db, User, IdentityDocument, AccessGrant
from app.models.schemas import AccessGrantCreate, AccessGrantOut
from app.services.auth import get_current_user
from app.services.blockchain import get_blockchain, Transaction, KeyManager

router = APIRouter(prefix="/api/access", tags=["Access Management"])


@router.post("/grants", response_model=AccessGrantOut, status_code=201)
async def create_grant(
    data: AccessGrantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Grant selective access to identity document fields."""
    # Verify document ownership
    doc_res = await db.execute(
        select(IdentityDocument).where(
            IdentityDocument.id == data.document_id,
            IdentityDocument.owner_id == current_user.id,
        )
    )
    doc = doc_res.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found or not owned by you")
    if doc.is_revoked is True:
        raise HTTPException(status_code=400, detail="Cannot grant access to a revoked document")

    expires_at = None
    if data.expires_hours:
        expires_at = time.time() + data.expires_hours * 3600

    bc = get_blockchain()
    tx_id = str(uuid.uuid4())
    tx = Transaction(
        tx_id=tx_id,
        user_id=str(current_user.id),
        action="SHARE",
        document_hash=str(doc.doc_hash),
        metadata={
            "grantee": data.grantee_identifier,
            "fields": data.fields_allowed,
            "expires_at": expires_at,
        },
        timestamp=time.time(),
    )
    tx.signature = KeyManager.sign(tx.signing_payload(), str(current_user.private_key_encrypted))
    bc.add_transaction(tx)
    bc.mine_block()

    grant = AccessGrant(
        id=str(uuid.uuid4()),
        grantor_id=current_user.id,
        grantee_identifier=data.grantee_identifier,
        document_id=data.document_id,
        fields_allowed=json.dumps(data.fields_allowed),
        expires_at=expires_at,
        tx_id=tx_id,
        created_at=time.time(),
    )
    db.add(grant)
    await db.commit()
    await db.refresh(grant)
    return _grant_out(grant)


@router.get("/grants", response_model=list[AccessGrantOut])
async def list_grants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AccessGrant).where(AccessGrant.grantor_id == current_user.id)
    )
    return [_grant_out(g) for g in result.scalars().all()]


@router.delete("/grants/{grant_id}")
async def revoke_grant(
    grant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AccessGrant).where(
            AccessGrant.id == grant_id,
            AccessGrant.grantor_id == current_user.id,
        )
    )
    grant = result.scalar_one_or_none()
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")

    # Record revocation on blockchain
    doc_res = await db.execute(select(IdentityDocument).where(IdentityDocument.id == grant.document_id))
    doc = doc_res.scalar_one_or_none()
    
    bc = get_blockchain()
    tx = Transaction(
        tx_id=str(uuid.uuid4()),
        user_id=str(current_user.id),
        action="REVOKE_GRANT",
        document_hash=str(doc.doc_hash) if doc else "N/A",
        metadata={"grant_id": grant_id, "grantee": grant.grantee_identifier},
        timestamp=time.time(),
    )
    tx.signature = KeyManager.sign(tx.signing_payload(), str(current_user.private_key_encrypted))
    bc.add_transaction(tx)
    bc.mine_block()

    await db.execute(
        update(AccessGrant).where(AccessGrant.id == grant_id).values(is_active=False)
    )
    await db.commit()
    return {"message": "Access grant revoked"}

def _grant_out(g: AccessGrant) -> AccessGrantOut:
    fields = []
    try:
        fields = json.loads(str(g.fields_allowed))
    except Exception:
        pass

    raw_expires = getattr(g, "expires_at", None)
    raw_created = getattr(g, "created_at", None)
    raw_tx_id   = getattr(g, "tx_id", None)

    return AccessGrantOut(
        id=str(getattr(g, "id", "")),
        grantee_identifier=str(getattr(g, "grantee_identifier", "")),
        document_id=str(getattr(g, "document_id", "")),
        fields_allowed=fields,
        expires_at=float(raw_expires) if raw_expires is not None else None,
        is_active=bool(getattr(g, "is_active", False)),
        tx_id=str(raw_tx_id) if raw_tx_id is not None else None,
        created_at=float(raw_created) if raw_created is not None else None,
    )