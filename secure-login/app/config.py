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

settings = Settings()