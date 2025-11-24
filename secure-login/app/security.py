from argon2 import PasswordHasher
from argon2.low_level import Type
from itsdangerous import Signer
from app.config import settings
import hashlib
import base64
import os
import pyotp
import qrcode
from io import BytesIO

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

# Funciones para 2FA/MFA con TOTP
def generate_totp_secret() -> str:
    """Genera un secreto TOTP aleatorio"""
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str, issuer: str = "Secure Login") -> str:
    """Genera la URI TOTP para el QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name=issuer
    )

def generate_qr_code(uri: str) -> bytes:
    """Genera un QR code como bytes PNG a partir de una URI TOTP"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

def verify_totp_code(secret: str, code: str) -> bool:
    """Verifica un código TOTP contra un secreto"""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        # Verificar con ventana de tiempo de ±1 intervalo (30 segundos)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False