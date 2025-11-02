from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy import select, update
from datetime import datetime, timedelta
from app.db import get_db
from app import models
from app.schemas import RegisterIn, LoginIn, ChangePasswordIn
from app.security import hash_password, verify_password, random_token, ua_fingerprint, hmac_sha256_hex
from app.csrf import make_csrf_token, validate_csrf
from app.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])

def set_cookie_session(resp: Response, sid: str):
    resp.set_cookie(
        key=settings.COOKIE_NAME,
        value=sid,
        httponly=True,
        secure=settings.COOKIE_SECURE,  # False para desarrollo local, True en producción
        samesite="lax",
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )

def set_cookie_csrf(resp: Response, csrf_value: str):
    resp.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_value,
        httponly=False,   # el frontend debe leerlo para enviarlo en el header X-CSRF-Token
        secure=settings.COOKIE_SECURE,  # False para desarrollo local, True en producción
        samesite="lax",
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )

def current_session(request: Request, db: OrmSession) -> models.Session | None:
    sid = request.cookies.get(settings.COOKIE_NAME)
    if not sid:
        return None
    s = db.get(models.Session, sid)
    if not s or s.revoked:
        return None
    return s

@router.post("/register", status_code=204)
def register(payload: RegisterIn, db: OrmSession = Depends(get_db)):
    # Validar que la contraseña no sea similar al email
    from app.schemas import validate_password_strength
    try:
        validate_password_strength(payload.password, payload.email)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    exists = db.scalar(select(models.User).where(models.User.email == payload.email.lower()))
    if exists:
        # no revelamos demasiado
        return Response(status_code=204)
    u = models.User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password)
    )
    db.add(u)
    db.flush()
    # acá podrías crear el token de verificación y "enviarlo"
    db.commit()
    # respondemos 204 aunque exista o no (para evitar enumeración)
    return Response(status_code=204)

@router.post("/login", status_code=204)
def login(payload: LoginIn, response: Response, request: Request, db: OrmSession = Depends(get_db)):
    user: models.User | None = db.scalar(select(models.User).where(models.User.email == payload.email.lower()))
    if not user:
        # respuesta uniforme
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # lockout simple
    if user.lock_until and user.lock_until > datetime.utcnow():
        raise HTTPException(status_code=429, detail="Cuenta temporalmente bloqueada")

    if not verify_password(user.password_hash, payload.password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= 5:
            user.lock_until = datetime.utcnow() + timedelta(minutes=15)
        db.add(user)
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # éxito: reset
    user.failed_logins = 0
    user.lock_until = None
    db.add(user)
    db.flush()

    # crear sesión
    csrf_secret = random_token(32)
    s = models.Session(
        user_id=user.id,
        ip=request.client.host if request.client else None,
        ua_hash=ua_fingerprint(request.headers.get("user-agent")),
        csrf_secret=csrf_secret
    )
    db.add(s)
    db.commit()

    # set cookies
    set_cookie_session(response, s.sid)
    set_cookie_csrf(response, make_csrf_token(csrf_secret))

    # auditar
    db.add(models.AuditEvent(user_id=user.id, event="login_success"))
    db.commit()
    
    response.status_code = 204
    return response

@router.delete("/session", status_code=204)
def logout(response: Response, request: Request, db: OrmSession = Depends(get_db)):
    s = current_session(request, db)
    if s:
        s.revoked = True
        db.add(s)
        db.add(models.AuditEvent(user_id=s.user_id, event="logout"))
        db.commit()
    # borrar cookie
    response.delete_cookie(settings.COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
    
    response.status_code = 204
    return response

@router.get("/me")
def me(request: Request, db: OrmSession = Depends(get_db)):
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    return {"user_id": s.user_id}

@router.post("/change-password", status_code=204)
def change_password(payload: ChangePasswordIn, request: Request, db: OrmSession = Depends(get_db)):
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    # CSRF para métodos state-changing
    validate_csrf(request, s.csrf_secret)

    user = db.get(models.User, s.user_id)
    if not user or not verify_password(user.password_hash, payload.old_password):
        raise HTTPException(status_code=400, detail="Contraseña actual inválida")

    # Validar que la nueva contraseña no sea similar al email
    from app.schemas import validate_password_strength
    try:
        validate_password_strength(payload.new_password, user.email)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user.password_hash = hash_password(payload.new_password)
    db.add(user)

    # logout global (revoca todas menos la actual)
    db.query(models.Session).filter(
        models.Session.user_id == user.id,
        models.Session.sid != s.sid
    ).update({models.Session.revoked: True})
    db.add(models.AuditEvent(user_id=user.id, event="password_changed"))
    db.commit()

    # rotar CSRF
    s.csrf_secret = random_token(32)
    db.add(s)
    db.commit()

    # setear nuevo CSRF cookie
    resp = Response(status_code=204)
    set_cookie_csrf(resp, make_csrf_token(s.csrf_secret))
    return resp