from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy import select, update, and_
from datetime import datetime, timedelta
import base64
from app.db import get_db
from app import models
from app.schemas import RegisterIn, LoginIn, ChangePasswordIn, ForgotPasswordIn, ResetPasswordIn, VerifyTotpCodeIn, EnableTotpIn, validate_password_strength
from app.security import hash_password, verify_password, random_token, ua_fingerprint, hmac_sha256_hex, generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp_code
from fastapi.responses import Response as FastAPIResponse
from app.csrf import make_csrf_token, validate_csrf
from app.config import settings
from app.utils_email_tokens import generate_email_token, send_password_reset_email

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

@router.post("/login")
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

    # Si el usuario tiene 2FA habilitado, crear token temporal y pedir código
    if user.totp_enabled and user.totp_secret:
        # Crear token temporal para verificación 2FA
        temp_token = random_token(32)
        temp_token_hash = hmac_sha256_hex(temp_token)
        
        pending = models.PendingTotpLogin(
            user_id=user.id,
            token_hash=temp_token_hash,
            expires_at=datetime.utcnow() + timedelta(minutes=5),  # 5 minutos para ingresar código
            ip=request.client.host if request.client else None,
            ua_hash=ua_fingerprint(request.headers.get("user-agent"))
        )
        db.add(pending)
        db.add(models.AuditEvent(user_id=user.id, event="login_pending_2fa", ip=pending.ip, ua_hash=pending.ua_hash))
        db.commit()
        
        # Retornar que necesita código 2FA
        return {"requires_2fa": True, "temp_token": temp_token}
    
    # Si no tiene 2FA, crear sesión directamente
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

@router.post("/forgot-password", status_code=204)
def forgot_password(payload: ForgotPasswordIn, request: Request, db: OrmSession = Depends(get_db)):
    # Respuesta uniforme para evitar enumeración
    email = payload.email.lower()
    user: models.User | None = db.scalar(select(models.User).where(models.User.email == email))
    if not user:
        return Response(status_code=204)

    # (opcional) rate-limit simple por usuario: 1 cada 5 min
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    recent = db.scalar(
        select(models.PasswordResetToken)
        .where(
            models.PasswordResetToken.user_id == user.id,
            models.PasswordResetToken.created_at >= five_min_ago
        )
    )
    if recent:
        # igual respondemos 204 sin revelar nada
        return Response(status_code=204)

    # generar token y guardar sólo el hash
    token, token_hash = generate_email_token()
    t = models.PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(seconds=settings.PASSWORD_RESET_TOKEN_TTL_SECONDS),
        ip=request.client.host if request.client else None,
        ua_hash=ua_fingerprint(request.headers.get("user-agent")),
    )
    db.add(t)
    db.add(models.AuditEvent(user_id=user.id, event="password_reset_requested", ip=t.ip, ua_hash=t.ua_hash))
    db.commit()

    # armar link al front (index.html escucha #reset?token=...)
    reset_link = f"{settings.FRONTEND_BASE_URL}/#reset?token={token}"
    send_password_reset_email(email, reset_link)

    return Response(status_code=204)


@router.post("/reset-password", status_code=204)
def reset_password(payload: ResetPasswordIn, request: Request, db: OrmSession = Depends(get_db)):
    token_hash = hmac_sha256_hex(payload.token)

    # Buscar token válido (no usado, no vencido)
    now = datetime.utcnow()
    prt: models.PasswordResetToken | None = db.scalar(
        select(models.PasswordResetToken).where(
            and_(
                models.PasswordResetToken.token_hash == token_hash,
                models.PasswordResetToken.used_at.is_(None),
                models.PasswordResetToken.expires_at > now,
            )
        )
    )
    if not prt:
        raise HTTPException(status_code=400, detail="Token inválido o expirado")

    user = db.get(models.User, prt.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Token inválido")

    # Validar fuerza y no-similitud con email
    try:
        validate_password_strength(payload.new_password, user.email)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Setear nueva password
    user.password_hash = hash_password(payload.new_password)
    db.add(user)

    # Marcar token como usado (single-use)
    prt.used_at = now
    db.add(prt)

    # Logout global (revoca TODAS las sesiones del usuario)
    db.query(models.Session).filter(models.Session.user_id == user.id).update({models.Session.revoked: True})

    db.add(models.AuditEvent(user_id=user.id, event="password_reset_success", ip=prt.ip, ua_hash=prt.ua_hash))
    db.commit()

    return Response(status_code=204)

# ========== Endpoints 2FA/MFA ==========

@router.post("/verify-2fa-login")
def verify_2fa_login_with_token(payload: dict, response: Response, request: Request, db: OrmSession = Depends(get_db)):
    """Verifica código 2FA usando temp_token del body"""
    temp_token = payload.get("temp_token")
    code = payload.get("code")
    
    if not temp_token or not code:
        raise HTTPException(status_code=400, detail="temp_token y code son requeridos")
    
    temp_token_hash = hmac_sha256_hex(temp_token)
    now = datetime.utcnow()
    
    pending = db.scalar(
        select(models.PendingTotpLogin).where(
            and_(
                models.PendingTotpLogin.token_hash == temp_token_hash,
                models.PendingTotpLogin.expires_at > now,
            )
        )
    )
    
    if not pending:
        raise HTTPException(status_code=400, detail="Token temporal inválido o expirado")
    
    user = db.get(models.User, pending.user_id)
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="Usuario inválido o 2FA no habilitado")
    
    # Verificar código TOTP
    if not verify_totp_code(user.totp_secret, code):
        db.add(models.AuditEvent(user_id=user.id, event="login_2fa_failed", ip=pending.ip, ua_hash=pending.ua_hash))
        db.commit()
        raise HTTPException(status_code=401, detail="Código 2FA inválido")
    
    # Eliminar token temporal
    db.delete(pending)
    
    # Crear sesión
    csrf_secret = random_token(32)
    s = models.Session(
        user_id=user.id,
        ip=request.client.host if request.client else None,
        ua_hash=ua_fingerprint(request.headers.get("user-agent")),
        csrf_secret=csrf_secret
    )
    db.add(s)
    db.commit()
    
    # Set cookies
    set_cookie_session(response, s.sid)
    set_cookie_csrf(response, make_csrf_token(csrf_secret))
    
    # Auditar
    db.add(models.AuditEvent(user_id=user.id, event="login_success_2fa", ip=pending.ip, ua_hash=pending.ua_hash))
    db.commit()
    
    response.status_code = 204
    return response

@router.get("/2fa/status")
def get_2fa_status(request: Request, db: OrmSession = Depends(get_db)):
    """Obtiene el estado de 2FA del usuario autenticado"""
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    user = db.get(models.User, s.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return {
        "enabled": user.totp_enabled or False,
        "configured": bool(user.totp_secret)
    }

@router.post("/2fa/enable")
def enable_2fa_start(request: Request, db: OrmSession = Depends(get_db)):
    """Inicia el proceso de habilitación de 2FA - genera secreto y QR"""
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    user = db.get(models.User, s.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA ya está habilitado")
    
    # Generar nuevo secreto
    secret = generate_totp_secret()
    user.totp_secret = secret
    # No habilitamos todavía hasta que verifique el código
    db.add(user)
    db.commit()
    
    # Generar URI y QR code
    uri = None
    qr_data_url = None
    
    try:
        uri = get_totp_uri(secret, user.email)
        qr_image = generate_qr_code(uri)
        qr_base64 = base64.b64encode(qr_image).decode()
        qr_data_url = f"data:image/png;base64,{qr_base64}"
    except Exception as e:
        # Si falla la generación del QR, aún retornamos el secreto para entrada manual
        import traceback
        print(f"❌ Error generando QR code: {e}")
        traceback.print_exc()
        # Intentar generar URI aunque falle el QR
        try:
            uri = get_totp_uri(secret, user.email)
        except:
            pass
    
    db.add(models.AuditEvent(user_id=user.id, event="2fa_enable_started"))
    db.commit()
    
    result = {
        "secret": secret,  # Para mostrar manualmente si es necesario
        "uri": uri,
        "qr_code": qr_data_url  # Puede ser None si falló la generación
    }
    
    return result

@router.post("/2fa/enable/verify")
def enable_2fa_verify(payload: EnableTotpIn, request: Request, db: OrmSession = Depends(get_db)):
    """Verifica código 2FA y habilita 2FA definitivamente"""
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    user = db.get(models.User, s.user_id)
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="Debe iniciar el proceso de habilitación primero")
    
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA ya está habilitado")
    
    # Verificar código
    if not verify_totp_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="Código 2FA inválido")
    
    # Habilitar 2FA
    user.totp_enabled = True
    db.add(user)
    db.add(models.AuditEvent(user_id=user.id, event="2fa_enabled"))
    db.commit()
    
    return Response(status_code=204)

@router.post("/2fa/disable", status_code=204)
def disable_2fa(payload: EnableTotpIn, request: Request, db: OrmSession = Depends(get_db)):
    """Deshabilita 2FA (requiere código de verificación)"""
    s = current_session(request, db)
    if not s:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    user = db.get(models.User, s.user_id)
    if not user or not user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA no está habilitado")
    
    # Verificar código antes de deshabilitar
    if not verify_totp_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="Código 2FA inválido")
    
    # Deshabilitar y limpiar secreto
    user.totp_enabled = False
    user.totp_secret = None
    db.add(user)
    
    # Logout global (revoca todas las sesiones)
    db.query(models.Session).filter(models.Session.user_id == user.id).update({models.Session.revoked: True})
    
    db.add(models.AuditEvent(user_id=user.id, event="2fa_disabled"))
    db.commit()
    
    # Borrar cookies
    resp = Response(status_code=204)
    resp.delete_cookie(settings.COOKIE_NAME, path="/")
    resp.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
    return resp
