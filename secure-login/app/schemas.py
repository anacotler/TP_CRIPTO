from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_core import PydanticCustomError
import re

def validate_password_strength(password: str, email: str = None) -> str:
    """
    Valida que la contraseña cumpla con los requisitos de seguridad:
    - Mínimo 12 caracteres
    - Al menos una letra
    - Al menos un número
    - Al menos un carácter especial
    - No debe ser similar al email/username
    """
    errors = []
    
    if len(password) < 12:
        errors.append("debe tener al menos 12 caracteres")
    
    if not re.search(r'[a-zA-Z]', password):
        errors.append("debe contener al menos una letra")
    
    if not re.search(r'\d', password):
        errors.append("debe contener al menos un número")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
        errors.append("debe contener al menos un carácter especial (!@#$%^&*...)")
    
    # Verificar que no sea similar al email
    if email:
        username = email.split('@')[0].lower()
        password_lower = password.lower()
        
        # Si el username está contenido en la password o viceversa
        if username in password_lower or password_lower in username:
            errors.append("no debe ser similar al nombre de usuario")
        
        # Similitud por subsecuencias largas (más de 4 caracteres consecutivos)
        if len(username) >= 4:
            for i in range(len(username) - 3):
                substring = username[i:i+4]
                if substring in password_lower:
                    errors.append("no debe contener partes del nombre de usuario")
                    break
    
    if errors:
        raise ValueError("La contraseña " + ", ".join(errors))
    
    return password

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str, info) -> str:
        # El email aún no está disponible en este punto durante la validación individual
        # Lo validaremos en el endpoint
        # Pero hacemos validaciones básicas aquí
        if len(v) < 12:
            raise ValueError("debe tener al menos 12 caracteres")
        if not re.search(r'[a-zA-Z]', v):
            raise ValueError("debe contener al menos una letra")
        if not re.search(r'\d', v):
            raise ValueError("debe contener al menos un número")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', v):
            raise ValueError("debe contener al menos un carácter especial (!@#$%^&*...)")
        return v

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class ChangePasswordIn(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12)
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("debe tener al menos 12 caracteres")
        if not re.search(r'[a-zA-Z]', v):
            raise ValueError("debe contener al menos una letra")
        if not re.search(r'\d', v):
            raise ValueError("debe contener al menos un número")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', v):
            raise ValueError("debe contener al menos un carácter especial (!@#$%^&*...)")
        return v