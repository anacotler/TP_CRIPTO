from argon2 import PasswordHasher
from argon2.low_level import Type
from itsdangerous import Signer
from app.config import settings
import hashlib
import base64
import os

# Argon2id con parámetros razonables (calibrables)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=96_000,  # 96 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)

def hash_password(plain: str) -> str:
    return ph.hash(plain)

def verify_password(hash_str: str, plain: str) -> bool:
    try:
        ph.verify(hash_str, plain)
        # rehash si quedó “viejo”
        if ph.check_needs_rehash(hash_str):
            return True  # (en login podemos actualizar)
        return True
    except Exception:
        return False

def random_token(nbytes: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")

def hmac_sha256_hex(value: str) -> str:
    return hashlib.sha256((settings.SECRET_KEY + value).encode()).hexdigest()

def ua_fingerprint(user_agent: str) -> str:
    # Guardamos un hash, no el UA completo (menos PII)
    return hmac_sha256_hex(user_agent or "")