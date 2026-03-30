"""Tests for the blockchain core and API endpoints."""
import pytest # pyright: ignore[reportMissingImports] # pyright: ignore[reportMissingImports]
import time
from app.services.blockchain import (
    Blockchain, Block, Transaction, KeyManager, hash_fields, hash_document
)


# ── Blockchain Core Tests ────────────────────────────────────────
def test_genesis_block():
    bc = Blockchain()
    assert len(bc.chain) == 1
    assert bc.chain[0].index == 0
    assert bc.chain[0].previous_hash == "0" * 64


def test_proof_of_work():
    bc = Blockchain()
    block = Block(index=1, transactions=[], previous_hash=bc.last_block.hash)
    h = bc.proof_of_work(block)
    assert h.startswith("0" * bc.DIFFICULTY)


def test_mine_block():
    bc = Blockchain()
    priv, pub = KeyManager.generate_key_pair()
    tx = Transaction(
        tx_id="test-tx-1", user_id="user-1", action="REGISTER",
        document_hash="abc123", metadata={}, timestamp=time.time()
    )
    tx.signature = KeyManager.sign(tx.signing_payload(), priv)
    bc.add_transaction(tx)
    block = bc.mine_block()
    assert block is not None
    assert len(bc.chain) == 2
    assert len(bc.pending_transactions) == 0


def test_chain_validity():
    bc = Blockchain()
    assert bc.is_chain_valid()
    priv, pub = KeyManager.generate_key_pair()
    tx = Transaction(
        tx_id="tx-valid", user_id="u1", action="REGISTER",
        document_hash="deadbeef", metadata={}, timestamp=time.time()
    )
    tx.signature = KeyManager.sign(tx.signing_payload(), priv)
    bc.add_transaction(tx)
    bc.mine_block()
    assert bc.is_chain_valid()


def test_chain_tamper_detection():
    bc = Blockchain()
    priv, pub = KeyManager.generate_key_pair()
    tx = Transaction(tx_id="tx-t", user_id="u1", action="REGISTER", document_hash="abc", metadata={}, timestamp=time.time())
    tx.signature = KeyManager.sign(tx.signing_payload(), priv)
    bc.add_transaction(tx)
    bc.mine_block()

    # Tamper with a transaction
    bc.chain[1].transactions[0]["document_hash"] = "tampered_hash"
    assert not bc.is_chain_valid()


# ── Key Manager Tests ────────────────────────────────────────────
def test_key_generation():
    priv, pub = KeyManager.generate_key_pair()
    assert "PRIVATE KEY" in priv
    assert "PUBLIC KEY" in pub


def test_sign_verify():
    priv, pub = KeyManager.generate_key_pair()
    data = "Hello BlockID"
    sig = KeyManager.sign(data, priv)
    assert KeyManager.verify(data, sig, pub)


def test_wrong_key_fails():
    priv1, pub1 = KeyManager.generate_key_pair()
    _, pub2 = KeyManager.generate_key_pair()
    sig = KeyManager.sign("test", priv1)
    assert not KeyManager.verify("test", sig, pub2)


# ── Hashing Tests ────────────────────────────────────────────────
def test_hash_fields_deterministic():
    fields = {"name": "Alice", "dob": "1990-01-01"}
    h1 = hash_fields(fields)
    h2 = hash_fields({"dob": "1990-01-01", "name": "Alice"})  # Different order
    assert h1 == h2  # Order-independent


def test_hash_fields_sensitivity():
    h1 = hash_fields({"name": "Alice"})
    h2 = hash_fields({"name": "alice"})
    assert h1 != h2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])