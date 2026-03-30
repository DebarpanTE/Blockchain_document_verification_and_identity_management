"""
Blockchain core implementation for identity management.
Implements a simple but functional blockchain with:
- SHA-256 hashing for blocks
- Digital signatures using RSA
- Proof-of-work consensus
- Chain validation
"""
import hashlib
import json
import time
from typing import List, Optional, Dict, Any, cast
from dataclasses import dataclass, field, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


@dataclass
class Transaction:
    """Represents a single identity transaction on the blockchain."""
    tx_id: str
    user_id: str
    action: str          # "REGISTER", "VERIFY", "REVOKE", "SHARE", "UPDATE"
    document_hash: str   # SHA-256 hash of the identity document
    metadata: Dict[str, Any]
    timestamp: float
    signature: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def signing_payload(self) -> str:
        """Returns the canonical string to sign (excludes signature itself)."""
        return json.dumps({
            "tx_id": self.tx_id,
            "user_id": self.user_id,
            "action": self.action,
            "document_hash": self.document_hash,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }, sort_keys=True)


@dataclass
class Block:
    """A single block in the blockchain."""
    index: int
    transactions: List[Dict]
    previous_hash: str
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash,
        }


class Blockchain:
    """
    Core blockchain for identity management.
    Uses Proof-of-Work with adjustable difficulty.
    """
    DIFFICULTY = 3  # Number of leading zeros required

    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            transactions=[],
            previous_hash="0" * 64,
            timestamp=1700000000.0,
        )
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def proof_of_work(self, block: Block) -> str:
        """Find a nonce such that hash starts with DIFFICULTY zeros."""
        block.nonce = 0
        computed = block.compute_hash()
        prefix = "0" * self.DIFFICULTY
        while not computed.startswith(prefix):
            block.nonce += 1
            computed = block.compute_hash()
        return computed

    def add_transaction(self, transaction: Transaction) -> bool:
        """Add a signed transaction to the pending pool."""
        self.pending_transactions.append(transaction.to_dict())
        return True

    def mine_block(self) -> Optional[Block]:
        """Mine pending transactions into a new block."""
        if not self.pending_transactions:
            return None

        block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.last_block.hash,
        )
        block.hash = self.proof_of_work(block)
        self.chain.append(block)
        self.pending_transactions = []
        return block

    def is_chain_valid(self) -> bool:
        """Validate the entire chain integrity."""
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.hash != curr.compute_hash():
                return False
            if curr.previous_hash != prev.hash:
                return False
            if not curr.hash.startswith("0" * self.DIFFICULTY):
                return False
        return True

    def get_user_transactions(self, user_id: str) -> List[Dict]:
        """Retrieve all transactions for a specific user."""
        result = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("user_id") == user_id:
                    result.append({**tx, "block_index": block.index, "block_hash": block.hash})
        return result

    def find_transaction(self, tx_id: str) -> Optional[Dict]:
        """Find a transaction by ID across all blocks."""
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("tx_id") == tx_id:
                    return {**tx, "block_index": block.index, "block_hash": block.hash}
        return None

    def to_dict(self) -> List[Dict]:
        return [block.to_dict() for block in self.chain]


class KeyManager:
    """Manages RSA key pairs for digital signatures."""

    @staticmethod
    def generate_key_pair() -> tuple[str, str]:
        """Generate RSA-2048 key pair. Returns (private_pem, public_pem)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem

    @staticmethod
    def sign(data: str, private_pem: str) -> str:
        """Sign data with private key. Returns base64-encoded signature."""
        private_key = serialization.load_pem_private_key(
            private_pem.encode(), password=None, backend=default_backend()
        )
        private_key = cast(RSAPrivateKey, private_key)
        signature = private_key.sign(
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def verify(data: str, signature_b64: str, public_pem: str) -> bool:
        """Verify a signature. Returns True if valid."""
        try:
            public_key = serialization.load_pem_public_key(
                public_pem.encode(), backend=default_backend()
            )
            public_key = cast(RSAPublicKey, public_key)
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, Exception):
            return False


def hash_document(content: bytes) -> str:
    """Compute SHA-256 hash of a document."""
    return hashlib.sha256(content).hexdigest()


def hash_fields(fields: Dict[str, str]) -> str:
    """Deterministically hash a dict of identity fields."""
    canonical = json.dumps(fields, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# Singleton blockchain instance (in production, use a DB-backed chain)
_blockchain_instance: Optional[Blockchain] = None


def get_blockchain() -> Blockchain:
    global _blockchain_instance
    if _blockchain_instance is None:
        _blockchain_instance = Blockchain()
    return _blockchain_instance