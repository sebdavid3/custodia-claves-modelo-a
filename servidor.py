"""servidor.py — Servidor de custodia de claves (Modelo A).

Responsabilidades (ver pasos del enunciado):

  Paso 1 (REGISTRO):  registra al cliente en db_servidor.json SIN sobrescribir
                      si ya existe, y responde con su clave pública pk_s (PEM).
  Paso 2 (SEMILLA):   genera s_v con generar_semilla_maestra(), la guarda
                      asociada a id_v y pk_v con "autorizado": False, y la
                      envía cifrada con RSA-OAEP sobre la pk_v recibida.
  Paso 5a (RECUPERAR): ante un evento de autorización, marca "autorizado": True
                      y reenvía s_v cifrada EXCLUSIVAMENTE con la pk_v guardada
                      en el Paso 1.

El servidor guarda su par RSA en disco (identidad persistente) y la base de
datos de clientes en db_servidor.json. La semilla se guarda en Base64 porque
el servidor es el custodio (key escrow); el cliente nunca la persiste.

Uso:
    python servidor.py                 # escucha en 127.0.0.1:50000
    python servidor.py --host 0.0.0.0 --puerto 50000
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket

import crypto_utils as cu
from generador_semillas import generar_semilla_maestra

# --------------------------------------------------------------------------- #
# Rutas de estado persistente
# --------------------------------------------------------------------------- #
DIR = os.path.dirname(os.path.abspath(__file__))
# Raíz de datos: por defecto junto al código; CRIPTO_DATA la reubica (contenedores).
BASE = os.environ.get("CRIPTO_DATA", DIR)
os.makedirs(BASE, exist_ok=True)
SK_PATH = os.path.join(BASE, "servidor_sk.pem")
PK_PATH = os.path.join(BASE, "servidor_pk.pem")
DB_PATH = os.path.join(BASE, "db_servidor.json")

HOST_DEF = "127.0.0.1"
PUERTO_DEF = 50000


# ===========================================================================
# Identidad RSA del servidor
# ===========================================================================
def cargar_o_crear_rsa():
    """Carga el par RSA del servidor; lo crea y guarda si no existe (Paso 1)."""
    if os.path.exists(SK_PATH) and os.path.exists(PK_PATH):
        with open(SK_PATH, "rb") as f:
            sk = cu.cargar_privada_pem(f.read())
        print("[servidor] Par RSA cargado de disco.")
        return sk
    sk = cu.generar_par_rsa()
    with open(SK_PATH, "wb") as f:
        f.write(cu.serializar_privada_pem(sk))
    with open(PK_PATH, "wb") as f:
        f.write(cu.serializar_publica_pem(sk.public_key()))
    print("[servidor] Par RSA generado y guardado.")
    return sk


# ===========================================================================
# Base de datos de clientes
# ===========================================================================
def cargar_db() -> dict:
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"clientes": {}}


def guardar_db(db: dict) -> None:
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


# ===========================================================================
# Manejadores de acciones
# ===========================================================================
def manejar_registro(db: dict, msg: dict, pk_s_pem: str) -> dict:
    """Paso 1: registra sin sobrescribir y responde pk_s."""
    id_v = msg["id_v"]
    pk_v = msg["pk_v"]
    clientes = db["clientes"]
    if id_v in clientes:
        print(f"[servidor] REGISTRO: {id_v} ya existía; no se sobrescribe.")
    else:
        clientes[id_v] = {"pk_v": pk_v, "s_v": None,
                          "autorizado": False, "entrega_inicial": False}
        guardar_db(db)
        print(f"[servidor] REGISTRO: nuevo cliente {id_v}.")
    return {"accion": "REGISTRO_OK", "pk_s_pem": pk_s_pem}


def manejar_solicitar_semilla(db: dict, msg: dict) -> dict:
    """Paso 2: genera (si falta) y entrega s_v cifrada con la pk_v guardada."""
    id_v = msg["id_v"]
    cliente = db["clientes"].get(id_v)
    if cliente is None:
        return {"accion": "ERROR", "detalle": "cliente no registrado"}

    # Entrega inicial ÚNICA: repetir el registro no habilita una segunda entrega.
    if cliente.get("entrega_inicial"):
        print(f"[servidor] SEMILLA: entrega inicial ya realizada para {id_v}; "
              f"se rechaza (debe usar recuperación por pago).")
        return {"accion": "ERROR",
                "detalle": "entrega inicial ya realizada; use recuperación por pago (RECUPERAR)"}

    if cliente["s_v"] is None:
        s_v = generar_semilla_maestra()                     # <-- Modelo A
        cliente["s_v"] = base64.b64encode(s_v).decode("ascii")
        cliente["autorizado"] = False
        print(f"[servidor] SEMILLA: generada y custodiada para {id_v} "
              f"(autorizado=False).")
    else:
        s_v = base64.b64decode(cliente["s_v"])
    cliente["entrega_inicial"] = True                       # marca la entrega
    guardar_db(db)

    pk_v = cu.cargar_publica_pem(cliente["pk_v"].encode("utf-8"))
    s_v_cifrada = cu.rsa_cifrar(pk_v, s_v)
    return {"accion": "SEMILLA",
            "id_v": id_v,
            "s_v_cifrada": base64.b64encode(s_v_cifrada).decode("ascii")}


def manejar_ack(db: dict, msg: dict) -> dict:
    id_v = msg["id_v"]
    print(f"[servidor] ACK recibido de {id_v}: el cliente posee s_v.")
    return {"accion": "ACK_OK"}


def manejar_recuperar(db: dict, msg: dict) -> dict:
    """Paso 5a: recuperación autorizada. Cifra s_v con la pk_v del Paso 1."""
    id_v = msg["id_v"]
    cliente = db["clientes"].get(id_v)
    if cliente is None:
        return {"accion": "ERROR", "detalle": "cliente no registrado"}
    if cliente["s_v"] is None:
        return {"accion": "ERROR", "detalle": "no hay semilla custodiada"}

    if not msg.get("evento_autorizacion"):
        print(f"[servidor] RECUPERAR denegado para {id_v}: sin autorización.")
        return {"accion": "DENEGADO", "detalle": "falta evento de autorización"}

    cliente["autorizado"] = True
    guardar_db(db)
    s_v = base64.b64decode(cliente["s_v"])
    pk_v = cu.cargar_publica_pem(cliente["pk_v"].encode("utf-8"))  # pk_v del Paso 1
    s_v_cifrada = cu.rsa_cifrar(pk_v, s_v)
    print(f"[servidor] RECUPERAR autorizado para {id_v}; s_v devuelta.")
    return {"accion": "SEMILLA_RECUPERADA",
            "id_v": id_v,
            "s_v_cifrada": base64.b64encode(s_v_cifrada).decode("ascii")}


DESPACHADOR = {
    "REGISTRO": lambda db, m, pk: manejar_registro(db, m, pk),
    "SOLICITAR_SEMILLA": lambda db, m, pk: manejar_solicitar_semilla(db, m),
    "ACK": lambda db, m, pk: manejar_ack(db, m),
    "RECUPERAR": lambda db, m, pk: manejar_recuperar(db, m),
}


# ===========================================================================
# Bucle principal
# ===========================================================================
def atender_conexion(conn: socket.socket, db: dict, pk_s_pem: str) -> None:
    while True:
        try:
            msg = cu.recibir_json(conn)
        except (ConnectionError, OSError):
            break
        accion = msg.get("accion")
        manejador = DESPACHADOR.get(accion)
        if manejador is None:
            cu.enviar_json(conn, {"accion": "ERROR", "detalle": f"acción desconocida: {accion}"})
            continue
        respuesta = manejador(db, msg, pk_s_pem)
        cu.enviar_json(conn, respuesta)


def main() -> None:
    ap = argparse.ArgumentParser(description="Servidor de custodia de claves (Modelo A).")
    ap.add_argument("--host", default=HOST_DEF)
    ap.add_argument("--puerto", type=int, default=PUERTO_DEF)
    args = ap.parse_args()

    sk = cargar_o_crear_rsa()
    pk_s_pem = cu.serializar_publica_pem(sk.public_key()).decode("ascii")
    db = cargar_db()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.puerto))
        s.listen()
        print(f"[servidor] Escuchando en {args.host}:{args.puerto}. Ctrl+C para salir.")
        try:
            while True:
                conn, addr = s.accept()
                print(f"[servidor] Conexión de {addr}")
                with conn:
                    atender_conexion(conn, db, pk_s_pem)
        except KeyboardInterrupt:
            print("\n[servidor] Detenido.")


if __name__ == "__main__":
    main()
