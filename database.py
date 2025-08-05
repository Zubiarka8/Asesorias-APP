import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Eliminar tablas existentes para recrearlas
cursor.execute('DROP TABLE IF EXISTS usuarios;')
cursor.execute('DROP TABLE IF EXISTS asesorias;')
cursor.execute('DROP TABLE IF EXISTS registros_asesorias;')

# Crear la tabla 'usuarios'
cursor.execute('''
    CREATE TABLE usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        dni TEXT UNIQUE NOT NULL
    );
''')

# Crear la tabla 'asesorias' con día y hora
cursor.execute('''
    CREATE TABLE asesorias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        titulo TEXT NOT NULL,
        descripcion TEXT NOT NULL,
        dia TEXT NOT NULL,
        hora TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES usuarios(id)
    );
''')

# Nueva tabla para los registros de usuarios a asesorías
cursor.execute('''
    CREATE TABLE registros_asesorias (
        user_id INTEGER NOT NULL,
        asesoria_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, asesoria_id),
        FOREIGN KEY (user_id) REFERENCES usuarios(id),
        FOREIGN KEY (asesoria_id) REFERENCES asesorias(id)
    );
''')

conn.commit()
conn.close()

print("Tablas 'usuarios', 'asesorias' y 'registros_asesorias' creadas exitosamente.")