from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import sqlite3

app = FastAPI(title="API de Marcación de Rondas")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Inicializar la base de datos SQLite
def init_db():
    conn = sqlite3.connect("rondas.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS marcaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_guardia TEXT,
            puesto TEXT,
            latitud REAL,
            longitud REAL,
            fecha_hora TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


class MarcacionRequest(BaseModel):
    nombre_guardia: str
    puesto: str | None = None
    latitud: float | None = None
    longitud: float | None = None


@app.post("/api/marcar")
def registrar_marcacion(datos: MarcacionRequest):
    hora_servidor = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Guardar en la base de datos SQLite
    conn = sqlite3.connect("rondas.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO marcaciones (nombre_guardia, puesto, latitud, longitud, fecha_hora)
        VALUES (?, ?, ?, ?, ?)
    """, (datos.nombre_guardia, datos.puesto, datos.latitud, datos.longitud, hora_servidor))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "mensaje": "Marcación guardada en la base de datos",
        "hora_registro": hora_servidor,
        "datos": datos.dict()
    }


@app.get("/api/marcaciones")
def listar_marcaciones():
    conn = sqlite3.connect("rondas.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM marcaciones ORDER BY id DESC")
    filas = cursor.fetchall()
    conn.close()
    return [dict(fila) for fila in filas]


@app.get("/")
def home():
    return {"status": "Servidor en la nube activo"}