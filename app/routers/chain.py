"""Blockchain explorer endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from app.models.schemas import BlockOut, ChainStatsOut
from app.services.blockchain import get_blockchain, Blockchain
from app.services.auth import get_current_user
from app.models.database import User

router = APIRouter(prefix="/api/chain", tags=["Blockchain Explorer"])


@router.get("/stats", response_model=ChainStatsOut)
async def chain_stats(current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    total_tx = sum(len(b.transactions) for b in bc.chain)
    return ChainStatsOut(
        total_blocks=len(bc.chain),
        total_transactions=total_tx,
        is_valid=bc.is_chain_valid(),
        pending_transactions=len(bc.pending_transactions),
        difficulty=bc.DIFFICULTY,
    )


@router.get("/blocks", response_model=list[BlockOut])
async def list_blocks(current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    return [
        BlockOut(
            index=b.index,
            hash=b.hash,
            previous_hash=b.previous_hash,
            timestamp=b.timestamp,
            nonce=b.nonce,
            transaction_count=len(b.transactions),
        )
        for b in bc.chain
    ]


@router.get("/blocks/{index}")
async def get_block(index: int, current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    if index < 0 or index >= len(bc.chain):
        raise HTTPException(status_code=404, detail="Block not found")
    return bc.chain[index].to_dict()


@router.get("/transactions/{tx_id}")
async def get_transaction(tx_id: str, current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    tx = bc.find_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return tx


@router.get("/validate")
async def validate_chain(current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    valid = bc.is_chain_valid()
    return {"is_valid": valid, "blocks": len(bc.chain), "message": "Chain integrity verified" if valid else "Chain tampered!"}


@router.get("/my-transactions")
async def my_transactions(current_user: User = Depends(get_current_user)):
    bc = get_blockchain()
    return bc.get_user_transactions(str(current_user.id))