import os
import math
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import jwt
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from dotenv import load_dotenv

load_dotenv()


# --------------------------------------------------
# CONFIGURACIÓN
# --------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")

if not DATABASE_URL:
    raise RuntimeError("Falta DATABASE_URL en .env")

if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET debe tener al menos 32 caracteres")

ALGORITHM = "HS256"
TOKEN_HOURS = 8

app = FastAPI(title="Sistema de Marcación de Rondas")
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
password_hash = PasswordHash.recommended()
security = HTTPBearer()


# --------------------------------------------------
# CONEXIÓN A NEON Y UTILIDADES GEOGRÁFICAS
# --------------------------------------------------

def conectar():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def calcular_distancia_haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calcula la distancia en metros entre dos coordenadas GPS."""
    radio_tierra_m = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = (
        math.sin(dphi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return radio_tierra_m * c


# --------------------------------------------------
# MODELOS
# --------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class GuardiaCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=200)
    zona_id: int = Field(gt=0)


class CambiarPassword(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class CambiarZona(BaseModel):
    zona_id: int = Field(gt=0)


class MarcacionRequest(BaseModel):
    qr_token: str = Field(min_length=20, max_length=200)
    latitud: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitud: float = Field(ge=-180, le=180, allow_inf_nan=False)
    # Se acepta cualquier precisión GPS positiva y válida.
    precision_metros: float = Field(gt=0, allow_inf_nan=False)


class CambiarEstado(BaseModel):
    activo: bool


class CrearPuntos(BaseModel):
    zona_id: int = Field(gt=0)
    cantidad: int = Field(default=5, ge=1, le=5)


class CalibrarPuntoRequest(BaseModel):
    latitud: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitud: float = Field(ge=-180, le=180, allow_inf_nan=False)
    radio_metros: float = Field(default=15.0, ge=5.0, le=100.0)


# --------------------------------------------------
# AUTENTICACIÓN Y TOKENS
# --------------------------------------------------

def crear_token(usuario):
    ahora = datetime.now(timezone.utc)

    datos = {
        "sub": str(usuario["id"]),
        "username": usuario["username"],
        "rol": usuario["rol"],
        "iat": ahora,
        "exp": ahora + timedelta(hours=TOKEN_HOURS)
    }

    return jwt.encode(datos, JWT_SECRET, algorithm=ALGORITHM)


def obtener_usuario(
    credenciales: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        datos = jwt.decode(
            credenciales.credentials,
            JWT_SECRET,
            algorithms=[ALGORITHM]
        )

        user_id = int(datos["sub"])

    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Sesión inválida o vencida"
        )

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, rol, zona_id, activo
                FROM usuarios
                WHERE id = %s
            """, (user_id,))

            usuario = cur.fetchone()

    if not usuario or not usuario["activo"]:
        raise HTTPException(
            status_code=401,
            detail="Usuario inexistente o desactivado"
        )

    return usuario


def solo_admin(usuario=Depends(obtener_usuario)):
    if usuario["rol"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="No tienes permisos de administrador"
        )

    return usuario


# --------------------------------------------------
# INICIO DE SESIÓN
# --------------------------------------------------

@app.post("/api/login")
def login(datos: LoginRequest):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, password_hash, rol,
                       zona_id, activo
                FROM usuarios
                WHERE username = %s
            """, (datos.username,))

            usuario = cur.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos"
        )

    if not password_hash.verify(
        datos.password,
        usuario["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos"
        )

    if not usuario["activo"]:
        raise HTTPException(
            status_code=403,
            detail="Esta cuenta está desactivada"
        )

    token = crear_token(usuario)

    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "usuario": {
            "id": usuario["id"],
            "username": usuario["username"],
            "rol": usuario["rol"],
            "zona_id": usuario["zona_id"]
        }
    }


# --------------------------------------------------
# CONSULTAR ZONAS
# --------------------------------------------------

@app.get("/api/zonas")
def listar_zonas(usuario=Depends(obtener_usuario)):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, nombre
                FROM zonas
                WHERE activa = TRUE
                ORDER BY id
            """)

            return cur.fetchall()


# --------------------------------------------------
# ADMIN: GENERACIÓN Y CALIBRACIÓN DE PUNTOS QR
# --------------------------------------------------

@app.post("/api/admin/puntos/generar")
def generar_puntos(
    datos: CrearPuntos,
    usuario: dict = Depends(solo_admin)
):
    with conectar() as conn:
        with conn.cursor() as cur:

            cur.execute(
                "SELECT id FROM zonas WHERE id = %s AND activa = TRUE",
                (datos.zona_id,)
            )
            zona = cur.fetchone()

            if not zona:
                raise HTTPException(
                    status_code=404,
                    detail="Zona no encontrada o inactiva"
                )

            cur.execute("""
                SELECT COUNT(*) AS total,
                       COALESCE(MAX(numero), 0) AS ultimo
                FROM puntos
                WHERE zona_id = %s
            """, (datos.zona_id,))

            resultado = cur.fetchone()
            total = resultado["total"]
            ultimo = resultado["ultimo"]

            if total + datos.cantidad > 5:
                raise HTTPException(
                    status_code=409,
                    detail="Esta zona ya tiene puntos o superaría el máximo de 5"
                )

            puntos_creados = []

            for numero in range(
                ultimo + 1,
                ultimo + datos.cantidad + 1
            ):
                nombre = f"Punto {numero}"

                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(
                    token.encode()
                ).hexdigest()

                cur.execute("""
                    INSERT INTO puntos (
                        zona_id,
                        numero,
                        nombre,
                        qr_token_hash,
                        activo
                    )
                    VALUES (%s, %s, %s, %s, TRUE)
                    RETURNING id
                """, (
                    datos.zona_id,
                    numero,
                    nombre,
                    token_hash
                ))

                punto = cur.fetchone()

                puntos_creados.append({
                    "id": punto["id"],
                    "numero": numero,
                    "nombre": nombre,
                    "qr_token": token
                })

    return {
        "mensaje": "Puntos QR creados correctamente",
        "zona_id": datos.zona_id,
        "puntos": puntos_creados
    }


@app.patch("/api/admin/puntos/{punto_id}/calibrar")
def calibrar_punto(
    punto_id: int,
    datos: CalibrarPuntoRequest,
    admin=Depends(solo_admin)
):
    """Guarda las coordenadas maestras calibradas y el radio permitido para un punto QR."""
    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE puntos
                SET latitud = %s,
                    longitud = %s,
                    radio_metros = %s
                WHERE id = %s
                RETURNING id, nombre, latitud, longitud, radio_metros
            """, (
                datos.latitud,
                datos.longitud,
                datos.radio_metros,
                punto_id
            ))

            punto = cur.fetchone()

    if not punto:
        raise HTTPException(
            status_code=404,
            detail="Punto QR no encontrado"
        )

    return {
        "mensaje": "Punto calibrado correctamente",
        "punto": punto
    }


# --------------------------------------------------
# ADMINISTRACIÓN DE GUARDIAS
# --------------------------------------------------

@app.post("/api/admin/guardias")
def crear_guardia(
    datos: GuardiaCreate,
    admin=Depends(solo_admin)
):

    with conectar() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT id
                FROM zonas
                WHERE id = %s AND activa = TRUE
            """, (datos.zona_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="La zona no existe o está desactivada"
                )

            cur.execute("""
                SELECT id
                FROM usuarios
                WHERE username = %s
            """, (datos.username,))

            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Ese nombre de usuario ya existe"
                )

            cur.execute("""
                INSERT INTO usuarios (
                    username,
                    password_hash,
                    rol,
                    zona_id
                )
                VALUES (%s, %s, 'guardia', %s)
                RETURNING id, username, rol, zona_id, activo
            """, (
                datos.username,
                password_hash.hash(datos.password),
                datos.zona_id
            ))

            guardia = cur.fetchone()

    return {
        "mensaje": "Guardia creado correctamente",
        "guardia": guardia
    }


@app.get("/api/admin/guardias")
def listar_guardias(admin=Depends(solo_admin)):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.rol,
                    u.zona_id,
                    z.nombre AS zona,
                    u.activo,
                    u.creado_en
                FROM usuarios u
                LEFT JOIN zonas z ON z.id = u.zona_id
                WHERE u.rol = 'guardia'
                ORDER BY u.id
            """)

            return cur.fetchall()


@app.patch("/api/admin/guardias/{guardia_id}/password")
def cambiar_password(
    guardia_id: int,
    datos: CambiarPassword,
    admin=Depends(solo_admin)
):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE usuarios
                SET password_hash = %s
                WHERE id = %s AND rol = 'guardia'
                RETURNING id
            """, (
                password_hash.hash(datos.password),
                guardia_id
            ))

            resultado = cur.fetchone()

    if not resultado:
        raise HTTPException(
            status_code=404,
            detail="Guardia no encontrado"
        )

    return {"mensaje": "Contraseña actualizada correctamente"}


@app.patch("/api/admin/guardias/{guardia_id}/zona")
def cambiar_zona(
    guardia_id: int,
    datos: CambiarZona,
    admin=Depends(solo_admin)
):

    with conectar() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT id
                FROM zonas
                WHERE id = %s AND activa = TRUE
            """, (datos.zona_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="La zona no existe o está desactivada"
                )

            cur.execute("""
                UPDATE usuarios
                SET zona_id = %s
                WHERE id = %s AND rol = 'guardia'
                RETURNING id
            """, (datos.zona_id, guardia_id))

            resultado = cur.fetchone()

    if not resultado:
        raise HTTPException(
            status_code=404,
            detail="Guardia no encontrado"
        )

    return {"mensaje": "Zona actualizada correctamente"}


@app.patch("/api/admin/guardias/{guardia_id}/estado")
def cambiar_estado(
    guardia_id: int,
    datos: CambiarEstado,
    admin=Depends(solo_admin)
):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE usuarios
                SET activo = %s
                WHERE id = %s AND rol = 'guardia'
                RETURNING id
            """, (datos.activo, guardia_id))

            resultado = cur.fetchone()

    if not resultado:
        raise HTTPException(
            status_code=404,
            detail="Guardia no encontrado"
        )

    return {
        "mensaje": "Estado actualizado correctamente",
        "activo": datos.activo
    }


# --------------------------------------------------
# MARCACIONES
# --------------------------------------------------

@app.post("/api/marcar")
def registrar_marcacion(
    datos: MarcacionRequest,
    usuario=Depends(obtener_usuario)
):
    # Solo los guardias pueden registrar rondas
    if usuario["rol"] != "guardia":
        raise HTTPException(
            status_code=403,
            detail="Solo los guardias pueden registrar marcaciones"
        )

    # Calcular el hash del QR recibido
    token_hash = hashlib.sha256(
        datos.qr_token.encode()
    ).hexdigest()

    with conectar() as conn:
        with conn.cursor() as cur:

            # Buscar el QR, sus coordenadas calibradas y comprobar que esté activo
            cur.execute("""
                SELECT
                    p.id AS punto_id,
                    p.zona_id,
                    p.nombre AS punto_nombre,
                    p.latitud,
                    p.longitud,
                    COALESCE(p.radio_metros, 15.0) AS radio_metros
                FROM puntos p
                INNER JOIN zonas z ON z.id = p.zona_id
                WHERE p.qr_token_hash = %s
                  AND p.activo = TRUE
                  AND z.activa = TRUE
            """, (token_hash,))

            punto = cur.fetchone()

            if not punto:
                raise HTTPException(
                    status_code=400,
                    detail="Código QR inválido o punto desactivado"
                )

            # Comprobar que el punto pertenece a la zona del guardia
            if usuario["zona_id"] != punto["zona_id"]:
                raise HTTPException(
                    status_code=403,
                    detail="Este punto no pertenece a tu zona asignada"
                )

            distancia_metros = None

            # Validar distancia GPS si el punto ya tiene coordenadas calibradas
            if punto["latitud"] is not None and punto["longitud"] is not None:
                distancia_metros = calcular_distancia_haversine(
                    datos.latitud,
                    datos.longitud,
                    punto["latitud"],
                    punto["longitud"]
                )

                # Radio base del puesto (ej. 12m en patios abiertos, 18m bajo tinglado)
                # + margen de incertidumbre reportado por el teléfono (tope 10m)
                tolerancia_efectiva = punto["radio_metros"] + min(datos.precision_metros, 10.0)

                if distancia_metros > tolerancia_efectiva:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Fuera de rango ({distancia_metros:.1f}m del punto; máx {tolerancia_efectiva:.1f}m)."
                    )

            # Guardar la hora local de Paraguay
            fecha_hora = datetime.now(
                ZoneInfo("America/Asuncion")
            ).replace(tzinfo=None)

            # Guardar la marcación
            # Guardar la marcación (incluyendo la distancia calculada al punto)
            cur.execute("""
                            INSERT INTO marcaciones (
                                nombre_guardia,
                                puesto,
                                latitud,
                                longitud,
                                fecha_hora,
                                user_id,
                                zona_id,
                                punto_id,
                                precision_metros,
                                distancia_metros
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            RETURNING id, fecha_hora
                        """, (
                usuario["username"],
                punto["punto_nombre"],
                datos.latitud,
                datos.longitud,
                fecha_hora,
                usuario["id"],
                punto["zona_id"],
                punto["punto_id"],
                datos.precision_metros,
                round(distancia_metros, 1) if distancia_metros is not None else None
            ))

            marcacion = cur.fetchone()

    return {
        "mensaje": "Marcación registrada correctamente",
        "marcacion_id": marcacion["id"],
        "guardia": usuario["username"],
        "punto": punto["punto_nombre"],
        "fecha_hora": marcacion["fecha_hora"].isoformat(),
        "precision_metros": datos.precision_metros,
        "distancia_metros": round(distancia_metros, 1) if distancia_metros is not None else None
    }


@app.get("/api/mis-marcaciones")
def mis_marcaciones(usuario=Depends(obtener_usuario)):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM marcaciones
                WHERE user_id = %s
                ORDER BY id DESC
            """, (usuario["id"],))

            return cur.fetchall()


@app.get("/api/marcaciones")
def todas_las_marcaciones(admin=Depends(solo_admin)):

    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM marcaciones
                ORDER BY id DESC
            """)

            return cur.fetchall()


# --------------------------------------------------
# INICIO
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "status": "Sistema de rondas activo",
        "version": "nueva"
    }