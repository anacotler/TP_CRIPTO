# Para la práctica, simulamos “enviar email”: generamos token y lo mostramos en log.
from app.security import random_token, hmac_sha256_hex

# Guardaríamos el hash en DB en tablas password_reset_tokens / verify_tokens.
# Para simplificar la práctica, dejamos el esqueleto.

def generate_email_token() -> tuple[str, str]:
    token = random_token(32)            # lo que se envía por email
    token_hash = hmac_sha256_hex(token) # lo que guardás en DB
    return token, token_hash