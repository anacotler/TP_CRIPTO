# # Para la práctica, simulamos “enviar email”: generamos token y lo mostramos en log.
# from app.security import random_token, hmac_sha256_hex

# # Guardaríamos el hash en DB en tablas password_reset_tokens / verify_tokens.
# # Para simplificar la práctica, dejamos el esqueleto.
# def generate_email_token() -> tuple[str, str]:
#     token = random_token(32)            # lo que se envía por email
#     token_hash = hmac_sha256_hex(token) # lo que guardás en DB (no guardar token plano)
#     return token, token_hash

# def send_password_reset_email(email: str, link: str):
#     # Simulación: lo logeamos a consola. Para producción, integrar SMTP/Sendgrid/etc.
#     print(f"[EMAIL] To: {email} | Subject: Reset de contraseña | Link: {link}")

import logging, smtplib, ssl
from email.message import EmailMessage
from email.utils import formataddr
from app.security import random_token, hmac_sha256_hex
from app.config import settings

logger = logging.getLogger("uvicorn.error")

def generate_email_token() -> tuple[str, str]:
    token = random_token(32)            # lo que se envía por email
    token_hash = hmac_sha256_hex(token) # lo que guardás en DB
    return token, token_hash

def send_password_reset_email(email: str, link: str):
    # Si no hay SMTP configurado, dejamos el log como fallback (dev)
    if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.info("[EMAIL-DEV] To: %s | Link: %s", email, link)
        return

    msg = EmailMessage()
    msg["Subject"] = "Reset de contraseña"
    msg["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL or settings.SMTP_USER))
    msg["To"] = email
    msg.set_content(
        f"""Hola,

Recibimos una solicitud para restablecer tu contraseña.

Para continuar, abrí este enlace (válido por tiempo limitado):
{link}

Si no fuiste vos, podés ignorar este mensaje.

— {settings.SMTP_FROM_NAME}
"""
    )

    try:
        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as s:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                s.send_message(msg)
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
                s.ehlo()
                if settings.SMTP_USE_TLS:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                s.send_message(msg)
        logger.info("[EMAIL] enviado a %s", email)
    except Exception as e:
        # fallback: no rompemos el flujo; mostramos el link en logs para no trabar la demo
        logger.error("Error enviando email: %s", e)
        logger.info("[EMAIL-DEV] To: %s | Link: %s", email, link)
