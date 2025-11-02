from fastapi import Request, HTTPException
from app.config import settings
import hmac, hashlib, base64

def make_csrf_token(secret: str) -> str:
    # token = base64url( HMAC(secret, "csrf") )
    sig = hmac.new(secret.encode(), b"csrf", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")

def validate_csrf(request: Request, csrf_secret: str):
    header = request.headers.get("x-csrf-token")
    if not header:
        raise HTTPException(status_code=403, detail="Missing CSRF token")
    expected = make_csrf_token(csrf_secret)
    if not hmac.compare_digest(header, expected):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")