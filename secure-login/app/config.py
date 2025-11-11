from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseModel):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change")
    COOKIE_NAME: str = os.getenv("COOKIE_NAME", "sid")
    CSRF_COOKIE_NAME: str = os.getenv("CSRF_COOKIE_NAME", "csrf")
    SESSION_TTL_SECONDS: int = int(os.getenv("SESSION_TTL_SECONDS", "1209600"))
    # Si querés Postgres: "postgresql+psycopg2://user:pass@localhost/db"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./secure_login.sqlite3")
    # Para desarrollo local sin HTTPS, usar False; en producción DEBE ser True
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"

    PASSWORD_RESET_TOKEN_TTL_SECONDS: int = int(os.getenv("PASSWORD_RESET_TOKEN_TTL_SECONDS", "1800"))  # 30 min
    FRONTEND_BASE_URL: str = os.getenv("FRONTEND_BASE_URL", "http://127.0.0.1:8000")

    # --- SMTP ---
    SMTP_HOST: str | None = os.getenv("SMTP_HOST", None)            # ej: smtp.gmail.com
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))             # 587 (TLS) o 465 (SSL)
    SMTP_USER: str | None = os.getenv("SMTP_USER", None)            # tu_email@gmail.com
    SMTP_PASSWORD: str | None = os.getenv("SMTP_PASSWORD", None)    # app password 16 chars
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "Secure Login")
    SMTP_FROM_EMAIL: str | None = os.getenv("SMTP_FROM_EMAIL", None)# puede ser igual a SMTP_USER
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_USE_SSL: bool = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

settings = Settings()