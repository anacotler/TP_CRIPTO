#!/usr/bin/env python3
"""
Script de migración para agregar columnas de 2FA a la base de datos existente.
Ejecutar: python migrate_2fa.py
"""

import sqlite3
import os
from pathlib import Path

# Ruta a la base de datos
DB_PATH = Path(__file__).parent / "secure_login.sqlite3"

def migrate_database():
    """Agrega las columnas de 2FA a la base de datos si no existen"""
    
    if not DB_PATH.exists():
        print(f"⚠️  Base de datos no encontrada en {DB_PATH}")
        print("   La base de datos se creará automáticamente al iniciar el servidor.")
        return
    
    print(f"📦 Migrando base de datos: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Verificar qué columnas existen en la tabla users
        cursor.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}
        
        changes_made = False
        
        # Agregar totp_secret si no existe
        if 'totp_secret' not in columns:
            print("   ➕ Agregando columna: totp_secret")
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR")
            changes_made = True
        else:
            print("Columna totp_secret ya existe")
        
        # Agregar totp_enabled si no existe
        if 'totp_enabled' not in columns:
            print("   ➕ Agregando columna: totp_enabled")
            cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0")
            changes_made = True
        else:
            print("Columna totp_enabled ya existe")
        
        # Verificar si existe la tabla pending_totp_logins
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='pending_totp_logins'
        """)
        
        if not cursor.fetchone():
            print("   ➕ Creando tabla: pending_totp_logins")
            cursor.execute("""
                CREATE TABLE pending_totp_logins (
                    id VARCHAR NOT NULL PRIMARY KEY,
                    user_id VARCHAR NOT NULL,
                    token_hash VARCHAR NOT NULL UNIQUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    ip VARCHAR,
                    ua_hash VARCHAR,
                    FOREIGN KEY(user_id) REFERENCES users (id)
                )
            """)
            cursor.execute("CREATE INDEX ix_pending_totp_logins_user_id ON pending_totp_logins (user_id)")
            cursor.execute("CREATE INDEX ix_pending_totp_logins_token_hash ON pending_totp_logins (token_hash)")
            changes_made = True
        else:
            print("Tabla pending_totp_logins ya existe")
        
        conn.commit()
        
        if changes_made:
            print("\nMigración completada exitosamente!")
        else:
            print("\nBase de datos ya está actualizada (no se necesitaron cambios)")
            
    except Exception as e:
        conn.rollback()
        print(f"\nError durante la migración: {e}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("MIGRACIÓN DE BASE DE DATOS PARA 2FA/MFA")
    print("=" * 60)
    migrate_database()
    print("=" * 60)

