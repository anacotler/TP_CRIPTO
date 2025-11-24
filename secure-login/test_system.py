#!/usr/bin/env python3
"""
Script de pruebas automatizadas para el sistema de login seguro.
Ejecutar: python test_system.py
"""

import requests
import json
import sys
from datetime import datetime
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    print("pyotp no está instalado. Las pruebas de 2FA se saltarán.")
    print("   Instalar con: pip install pyotp")

BASE_URL = "http://127.0.0.1:8000"
TEST_EMAIL = f"autotest_{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com"
TEST_PASSWORD = "SecurePass2024!@#"
NEW_PASSWORD = "NewSecurePass456$%^"

def print_test(name):
    print(f"\n{'='*60}")
    print(f"Test: {name}")
    print(f"{'='*60}")

def print_success(msg):
    print(f"{msg}")

def print_error(msg):
    print(f"{msg}")

def print_info(msg):
    print(f"{msg}")

def test_register():
    """Test 1: Registro de usuario"""
    print_test("Registro de usuario")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            timeout=5
        )
        if response.status_code == 204:
            print_success(f"Usuario registrado correctamente: {TEST_EMAIL}")
            return True
        else:
            print_error(f"Registro falló: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.ConnectionError:
        print_error("No se pudo conectar al servidor. ¿Está ejecutándose?")
        return False
    except Exception as e:
        print_error(f"Error inesperado: {e}")
        return False

def test_register_weak_password():
    """Test 2: Rechazo de contraseña débil"""
    print_test("Validación de contraseña débil")
    weak_passwords = [
        ("corta", "Muy corta"),
        ("SinNumeros!", "Sin números"),
        ("SinSimbolos123", "Sin símbolos"),
        ("123456789012", "Solo números"),
    ]
    
    all_passed = True
    for password, description in weak_passwords:
        try:
            response = requests.post(
                f"{BASE_URL}/auth/register",
                json={"email": f"test_{description.replace(' ', '_')}@example.com", "password": password},
                timeout=5
            )
            if response.status_code == 400 or response.status_code == 422:
                print_success(f"Contraseña débil rechazada correctamente: {description}")
            else:
                print_error(f"Contraseña débil aceptada (no debería): {description}")
                all_passed = False
        except Exception as e:
            print_error(f"Error probando contraseña débil: {e}")
            all_passed = False
    
    return all_passed

def test_login():
    """Test 3: Login exitoso"""
    print_test("Login exitoso")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            timeout=5
        )
        if response.status_code == 204:
            cookies = response.cookies
            if 'sid' in cookies and 'csrf' in cookies:
                print_success("Login exitoso con cookies de sesión y CSRF correctamente")
                return cookies
            else:
                print_error("Login exitoso pero faltan cookies")
                return None
        else:
            print_error(f"Login falló: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print_error(f"Error en login: {e}")
        return None

def test_login_wrong_password():
    """Test 4: Login con contraseña incorrecta"""
    print_test("Login con contraseña incorrecta")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": "WrongPassword123!@#"},
            timeout=5
        )
        if response.status_code == 401:
            print_success("Login rechazado correctamente con contraseña incorrecta")
            return True
        else:
            print_error(f"Login no rechazado como debería: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_me(cookies):
    """Test 5: Verificación de sesión"""
    print_test("Verificación de sesión activa")
    if not cookies:
        print_error("No hay cookies para probar")
        return False
    
    try:
        response = requests.get(f"{BASE_URL}/auth/me", cookies=cookies, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'user_id' in data:
                print_success(f"Sesión activa - User ID: {data['user_id']}")
                return True
            else:
                print_error("Respuesta sin user_id")
                return False
        else:
            print_error(f"Verificación de sesión falló: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_change_password(cookies):
    """Test 6: Cambio de contraseña con CSRF"""
    print_test("Cambio de contraseña")
    if not cookies:
        print_error("No hay cookies para probar")
        return False
    
    csrf_token = cookies.get('csrf')
    if not csrf_token:
        print_error("No se encontró token CSRF en cookies")
        return False
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/change-password",
            json={"old_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
            cookies=cookies,
            headers={"X-CSRF-Token": csrf_token},
            timeout=5
        )
        if response.status_code == 204:
            print_success("Contraseña cambiada exitosamente")
            return True
        else:
            print_error(f"Cambio de contraseña falló: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_change_password_without_csrf(cookies):
    """Test 7: Cambio de contraseña sin CSRF (debe fallar)"""
    print_test("Protección CSRF - cambio sin token")
    if not cookies:
        print_error("No hay cookies para probar")
        return False
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/change-password",
            json={"old_password": NEW_PASSWORD, "new_password": "AnotherPassword123!@#"},
            cookies=cookies,
            # Sin header X-CSRF-Token
            timeout=5
        )
        if response.status_code == 403:
            print_success("Cambio de contraseña rechazado sin CSRF (correcto)")
            return True
        else:
            print_error(f"Cambio de contraseña no rechazado como debería: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_logout(cookies):
    """Test 8: Logout"""
    print_test("Logout exitoso")
    if not cookies:
        print_error("No hay cookies para probar")
        return False
    
    try:
        response = requests.delete(f"{BASE_URL}/auth/session", cookies=cookies, timeout=5)
        if response.status_code == 204:
            print_success("Logout exitoso")
            # Verificar que la sesión está cerrada
            response2 = requests.get(f"{BASE_URL}/auth/me", cookies=cookies, timeout=5)
            if response2.status_code == 401:
                print_success("Sesión invalidada correctamente")
                return True
            else:
                print_error("Sesión no invalidada después de logout")
                return False
        else:
            print_error(f"Logout falló: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_security_headers():
    """Test 9: Headers de seguridad"""
    print_test("Headers de seguridad")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        headers = response.headers
        
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
        
        all_present = True
        for header, expected_value in security_headers.items():
            if header in headers:
                if expected_value.lower() in headers[header].lower():
                    print_success(f"{header}: {headers[header]}")
                else:
                    print_error(f"{header} presente pero con valor incorrecto: {headers[header]}")
                    all_present = False
            else:
                print_error(f"{header} no presente")
                all_present = False
        
        if "Content-Security-Policy" in headers:
            print_success(f"Content-Security-Policy presente")
        else:
            print_error("Content-Security-Policy no presente")
            all_present = False
        
        return all_present
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_2fa_status(cookies):
    """Test 10: Verificar estado de 2FA"""
    print_test("Estado de 2FA obtenido correctamente")
    if not cookies:
        print_error("No hay cookies para probar")
        return False
    
    try:
        response = requests.get(f"{BASE_URL}/auth/2fa/status", cookies=cookies, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'enabled' in data and 'configured' in data:
                print_success(f"Estado 2FA obtenido: enabled={data['enabled']}, configured={data['configured']}")
                return True
            else:
                print_error("Respuesta sin campos esperados")
                return False
        else:
            print_error(f"Error obteniendo estado 2FA: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def test_enable_2fa(cookies):
    """Test 11: Habilitar 2FA"""
    print_test("Habilitar 2FA exitosamente")
    if not cookies:
        print_error("No hay cookies para probar")
        return None
    
    if not PYOTP_AVAILABLE:
        print_info("Saltando prueba: pyotp no disponible")
        return None
    
    try:
        # Iniciar habilitación
        response = requests.post(f"{BASE_URL}/auth/2fa/enable", cookies=cookies, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'secret' in data and 'qr_code' in data:
                print_success("QR code y secreto generados")
                secret = data['secret']
                
                # Generar código TOTP válido
                totp = pyotp.TOTP(secret)
                code = totp.now()
                
                # Verificar código y habilitar
                csrf_token = cookies.get('csrf')
                response2 = requests.post(
                    f"{BASE_URL}/auth/2fa/enable/verify",
                    json={"code": code},
                    cookies=cookies,
                    headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
                    timeout=5
                )
                
                if response2.status_code == 204:
                    print_success("2FA habilitado exitosamente")
                    return secret
                else:
                    print_error(f"Error verificando código: {response2.status_code} - {response2.text}")
                    return None
            else:
                print_error("Respuesta sin secret o qr_code")
                return None
        else:
            print_error(f"Error iniciando habilitación: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print_error(f"Error: {e}")
        return None

def test_login_with_2fa(secret):
    """Test 12: Login con 2FA habilitado"""
    print_test("Login con 2FA exitosamente")
    if not secret:
        print_info("Saltando prueba: 2FA no habilitado correctamente")
        return None
    
    if not PYOTP_AVAILABLE:
        print_info("Saltando prueba: pyotp no disponible correctamente")
        return None
    
    try:
        # Primero login normal (debe requerir 2FA)
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": NEW_PASSWORD},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('requires_2fa') and 'temp_token' in data:
                print_success("Login requiere 2FA (correcto)")
                temp_token = data['temp_token']
                
                # Generar código TOTP
                totp = pyotp.TOTP(secret)
                code = totp.now()
                
                # Verificar código 2FA
                response2 = requests.post(
                    f"{BASE_URL}/auth/verify-2fa-login",
                    json={"temp_token": temp_token, "code": code},
                    timeout=5
                )
                
                if response2.status_code == 204:
                    cookies = response2.cookies
                    if 'sid' in cookies:
                        print_success("Login con 2FA exitoso")
                        return cookies
                    else:
                        print_error("Login exitoso pero sin cookies")
                        return None
                else:
                    print_error(f"Error verificando 2FA: {response2.status_code} - {response2.text}")
                    return None
            else:
                print_error("Login no requiere 2FA cuando debería")
                return None
        else:
            print_error(f"Error en login: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print_error(f"Error: {e}")
        return None

def test_disable_2fa(cookies, secret):
    """Test 13: Deshabilitar 2FA"""
    print_test("Deshabilitar 2FA")
    if not cookies or not secret:
        print_info("Saltando prueba: no hay cookies o secreto")
        return False
    
    if not PYOTP_AVAILABLE:
        print_info("Saltando prueba: pyotp no disponible")
        return False
    
    try:
        # Generar código TOTP
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        csrf_token = cookies.get('csrf')
        response = requests.post(
            f"{BASE_URL}/auth/2fa/disable",
            json={"code": code},
            cookies=cookies,
            headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
            timeout=5
        )
        
        if response.status_code == 204:
            print_success("2FA deshabilitado exitosamente")
            return True
        else:
            print_error(f"Error deshabilitando 2FA: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("INICIANDO PRUEBAS AUTOMATIZADAS DEL SISTEMA DE LOGIN SEGURO")
    print("="*60)
    print_info(f"Servidor: {BASE_URL}")
    print_info(f"Email de prueba: {TEST_EMAIL}")
    
    results = []
    
    # Ejecutar tests
    results.append(("Registro", test_register()))
    results.append(("Validación de contraseña débil", test_register_weak_password()))
    
    cookies = test_login()
    results.append(("Login", cookies is not None))
    
    results.append(("Login con contraseña incorrecta", test_login_wrong_password()))
    
    if cookies:
        results.append(("Verificación de sesión", test_me(cookies)))
        results.append(("Cambio de contraseña", test_change_password(cookies)))
        results.append(("Protección CSRF", test_change_password_without_csrf(cookies)))
        
        # Pruebas de 2FA
        results.append(("Estado de 2FA", test_2fa_status(cookies)))
        secret = test_enable_2fa(cookies)
        results.append(("Habilitar 2FA", secret is not None))
        
        if secret:
            # Cerrar sesión antes de probar login con 2FA
            requests.delete(f"{BASE_URL}/auth/session", cookies=cookies, timeout=5)
            
            # Probar login con 2FA
            cookies_2fa = test_login_with_2fa(secret)
            results.append(("Login con 2FA", cookies_2fa is not None))
            
            if cookies_2fa:
                # Deshabilitar 2FA
                results.append(("Deshabilitar 2FA", test_disable_2fa(cookies_2fa, secret)))
        
        results.append(("Logout", test_logout(cookies)))
    
    results.append(("Headers de seguridad", test_security_headers()))
    
    # Resumen
    print("\n" + "="*60)
    print("RESUMEN DE PRUEBAS AUTOMATIZADAS")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "PASÓ" if result else "FALLÓ"
        print(f"{status}: {test_name}")
    
    print("\n" + "="*60)
    print(f"Total: {passed}/{total} pruebas pasaron")
    print("="*60)
    
    if passed == total:
        print_success("Todas las pruebas pasaron correctamente")
        return 0
    else:
        print_error(f"Fallaron {total - passed} pruebas")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nPruebas interrumpidas por el usuario")
        sys.exit(1)

