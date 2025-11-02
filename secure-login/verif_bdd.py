import sqlite3

conn = sqlite3.connect("secure_login.sqlite3")
cur = conn.cursor()

print("Tablas en la base de datos:")

# ver tablas
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cur.fetchall())


print("Datos en la tabla 'users':")
# ver datos de una tabla
cur.execute("SELECT * FROM users;")   # cambiá 'users' por la que te aparezca
print(cur.fetchall())

print("Datos detallados en la tabla 'users':")

# ver los datos mas detalladamente
cur.execute("PRAGMA table_info(users);")
columns = [col[1] for col in cur.fetchall()]
cur.execute("SELECT * FROM users;")
rows = cur.fetchall()
for row in rows:
    record = dict(zip(columns, row))
    print(record)

#datos de sesiones
print("Datos en la tabla 'sessions':")
cur.execute("SELECT * FROM sessions;")
print(cur.fetchall())

conn.close()
