from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Integer, Text
from sqlalchemy.dialects.sqlite import BLOB as SQLITE_BLOB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db import Base
import uuid

def uuid_str():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uuid_str)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    password_algo = Column(String, default="argon2id", nullable=False)
    email_verified_at = Column(DateTime, nullable=True)
    failed_logins = Column(Integer, default=0)
    lock_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class Session(Base):
    __tablename__ = "sessions"
    sid = Column(String, primary_key=True, default=uuid_str)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())
    last_seen_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    ip = Column(String, nullable=True)
    ua_hash = Column(String, nullable=True)
    csrf_secret = Column(String, nullable=False)  # base64 string
    revoked = Column(Boolean, default=False)
    user = relationship("User", lazy="joined")

class AuditEvent(Base):
    __tablename__ = "audit_security_events"
    id = Column(String, primary_key=True, default=uuid_str)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    event = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    ua_hash = Column(String, nullable=True)
    meta = Column(String, nullable=True)  # JSON string si querés
    created_at = Column(DateTime, server_default=func.now())