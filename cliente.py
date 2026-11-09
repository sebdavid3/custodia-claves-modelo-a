"""cliente.py — Cliente/Víctima (Modelo A).

Dos modos de ejecución:

  cifrado (por defecto)
      Paso 1  Registra su par RSA (lo crea si no existe) y su id_v, envía
              REGISTRO y recibe pk_s.
      Paso 2  Solicita la semilla, descifra s_v con sk_v y la mantiene SOLO en
              memoria RAM (nunca en disco), y envía ACK.
      Paso 3  Cifra todos los archivos de archivos_trabajo/ con contadores
              i = 0,1,2..., escribe los .enc.json en archivos_cifrados/ y, al
              terminar, borra s_v y las K_i de memoria. Conserva una copia de
              los originales en archivos_originales/ para la comparación final.

  recuperacion_servidor  (--modo recuperacion_servidor)
      Paso 4/5a  Carga id_v y sk_v de disco, envía RECUPERAR con
                 evento_autorizacion=True y descifra la s_v devuelta.
      Paso 6     Regenera cada K_i, verifica tag GCM y AAD, escribe los
                 archivos válidos en archivos_recuperados/ y los compara byte a
                 byte (y por SHA-256) contra archivos_originales/.

Uso:
    python cliente.py
    python cliente.py --modo recuperacion_servidor
    python cliente.py --host 127.0.0.1 --puerto 50000      # p.ej. apuntar al proxy
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import socket
import uuid

import crypto_utils as cu

# --------------------------------------------------------------------------- #
# Rutas de estado y carpetas de trabajo
# --------------------------------------------------------------------------- #
DIR = os.path.dirname(os.path.abspath(__file__))
# Raíz de datos: por defecto junto al código; CRIPTO_DATA la reubica (contenedores).
BASE = os.environ.get("CRIPTO_DATA", DIR)
os.makedirs(BASE, exist_ok=True)
SK_PATH = os.path.join(BASE, "cliente_sk.pem")
PK_PATH = os.path.join(BASE, "cliente_pk.pem")
ID_PATH = os.path.join(BASE, "cliente_id.txt")

DIR_TRABAJO = os.path.join(BASE, "archivos_trabajo")
DIR_CIFRADOS = os.path.join(BASE, "archivos_cifrados")
DIR_ORIGINALES = os.path.join(BASE, "archivos_originales")
DIR_RECUPERADOS = os.path.join(BASE, "archivos_recuperados")

HOST_DEF = "127.0.0.1"
PUERTO_DEF = 50000


# ===========================================================================
# Identidad persistente del cliente
# ===========================================================================
def cargar_o_crear_identidad():
    """Devuelve (sk_v, id_v). Crea y guarda el par RSA y el id_v si no existen."""
    if os.path.exists(SK_PATH) and os.path.exists(ID_PATH):
        with open(SK_PATH, "rb") as f:
            sk = cu.cargar_privada_pem(f.read())
        with open(ID_PATH, "r", encoding="utf-8") as f:
            id_v = f.read().strip()
        print(f"[cliente] Identidad cargada. id_v={id_v}")
        return sk, id_v

    sk = cu.generar_par_rsa()
    with open(SK_PATH, "wb") as f:
        f.write(cu.serializar_privada_pem(sk))
    with open(PK_PATH, "wb") as f:
        f.write(cu.serializar_publica_pem(sk.public_key()))
    id_v = str(uuid.uuid4())
    with open(ID_PATH, "w", encoding="utf-8") as f:
        f.write(id_v)
    print(f"[cliente] Identidad creada. id_v={id_v}")
    return sk, id_v


def _borrar_segura(ba: bytearray) -> None:
    """Sobrescribe con ceros un bytearray en memoria (borrado best-effort)."""
    for i in range(len(ba)):
        ba[i] = 0


def _listar_ordenado(carpeta: str) -> list[str]:
    return sorted(
        n for n in os.listdir(carpeta)
        if os.path.isfile(os.path.join(carpeta, n))
    )


# ===========================================================================
# Modo cifrado (Pasos 1, 2, 3)
# ===========================================================================
def modo_cifrado(host: str, puerto: int) -> None:
    sk, id_v = cargar_o_crear_identidad()
    pk_v_pem = cu.serializar_publica_pem(sk.public_key()).decode("ascii")

    os.makedirs(DIR_TRABAJO, exist_ok=True)
    os.makedirs(DIR_CIFRADOS, exist_ok=True)
    os.makedirs(DIR_ORIGINALES, exist_ok=True)

    archivos = _listar_ordenado(DIR_TRABAJO)
    if not archivos:
        print(f"[cliente] No hay archivos en {DIR_TRABAJO}. "
              f"Coloca archivos y vuelve a ejecutar.")
        return

    with socket.create_connection((host, puerto)) as s:
        # ---- Paso 1: REGISTRO ----
        cu.enviar_json(s, {"accion": "REGISTRO", "id_v": id_v, "pk_v": pk_v_pem})
        r = cu.recibir_json(s)
        if r.get("accion") != "REGISTRO_OK":
            print(f"[cliente] Registro falló: {r}")
            return
        print("[cliente] Paso 1 OK: registrado; pk_s recibida.")

        # ---- Paso 2: SEMILLA ----
        cu.enviar_json(s, {"accion": "SOLICITAR_SEMILLA", "id_v": id_v})
        r = cu.recibir_json(s)
        if r.get("accion") != "SEMILLA":
            print(f"[cliente] No se recibió semilla: {r}")
            return
        s_v_cifrada = base64.b64decode(r["s_v_cifrada"])
        s_v = bytearray(cu.rsa_descifrar(sk, s_v_cifrada))   # solo en RAM
        print(f"[cliente] Paso 2 OK: s_v descifrada en memoria ({len(s_v)} bytes).")

        cu.enviar_json(s, {"accion": "ACK", "id_v": id_v})
        r = cu.recibir_json(s)
        print(f"[cliente] ACK confirmado por el servidor: {r.get('accion')}")

    # ---- Paso 3: cifrado de archivos ----
    claves_en_memoria: list[bytearray] = []
    print(f"[cliente] Paso 3: cifrando {len(archivos)} archivo(s)...")
    for i, nombre in enumerate(archivos):
        ruta_in = os.path.join(DIR_TRABAJO, nombre)
        with open(ruta_in, "rb") as f:
            plaintext = f.read()

        k_i = bytearray(cu.derivar_clave(bytes(s_v), i))
        claves_en_memoria.append(k_i)
        aad = cu.construir_aad(id_v, i)
        nonce, ciphertext, tag = cu.aes_cifrar(bytes(k_i), plaintext, aad)

        contenedor = cu.empaquetar_enc(id_v, i, nombre, nonce, tag, ciphertext)
        ruta_out = os.path.join(DIR_CIFRADOS, f"{i:04d}_{nombre}.enc.json")
        cu.guardar_enc(ruta_out, contenedor)

        # Conservar el original para la comparación del Paso 6.
        shutil.copy2(ruta_in, os.path.join(DIR_ORIGINALES, nombre))
        print(f"   [i={i}] {nombre} -> {os.path.basename(ruta_out)}")

    # ---- Borrado de material secreto de memoria ----
    for k in claves_en_memoria:
        _borrar_segura(k)
    _borrar_segura(s_v)
    del claves_en_memoria, s_v
    print("[cliente] Paso 3 OK: s_v y las K_i borradas de memoria. "
          "El mensaje OAEP inicial no se guardó en disco.")


# ===========================================================================
# Modo recuperación autorizada (Pasos 4, 5a, 6)
# ===========================================================================
def modo_recuperacion(host: str, puerto: int) -> None:
    if not (os.path.exists(SK_PATH) and os.path.exists(ID_PATH)):
        print("[cliente] No existe identidad en disco. Ejecuta primero el modo cifrado.")
        return
    with open(SK_PATH, "rb") as f:
        sk = cu.cargar_privada_pem(f.read())
    with open(ID_PATH, "r", encoding="utf-8") as f:
        id_v = f.read().strip()
    print(f"[cliente] Recuperación: id_v={id_v} y sk_v cargados de disco.")

    # ---- Paso 4/5a: RECUPERAR ----
    with socket.create_connection((host, puerto)) as s:
        cu.enviar_json(s, {"accion": "RECUPERAR", "id_v": id_v,
                           "evento_autorizacion": True})
        r = cu.recibir_json(s)
        if r.get("accion") != "SEMILLA_RECUPERADA":
            print(f"[cliente] Recuperación no autorizada / error: {r}")
            return
        s_v_cifrada = base64.b64decode(r["s_v_cifrada"])
        s_v = bytearray(cu.rsa_descifrar(sk, s_v_cifrada))
        print(f"[cliente] Paso 5a OK: s_v recuperada en memoria ({len(s_v)} bytes).")

    # ---- Paso 6: descifrado, verificación y comparación ----
    os.makedirs(DIR_RECUPERADOS, exist_ok=True)
    cifrados = _listar_ordenado(DIR_CIFRADOS)
    if not cifrados:
        print(f"[cliente] No hay .enc.json en {DIR_CIFRADOS}.")
        _borrar_segura(s_v)
        return

    total = ok = fallos = iguales = 0
    print(f"[cliente] Paso 6: descifrando y comparando {len(cifrados)} archivo(s)...")
    for nombre_enc in cifrados:
        total += 1
        datos = cu.cargar_enc(os.path.join(DIR_CIFRADOS, nombre_enc))
        i = datos["contador_i"]
        k_i = cu.derivar_clave(bytes(s_v), i)
        aad = cu.construir_aad(datos["id_v"], i)
        try:
            plaintext = cu.aes_descifrar(k_i, datos["nonce"], datos["ciphertext"],
                                         datos["tag"], aad)
        except cu.InvalidTag:
            fallos += 1
            print(f"   [i={i}] {datos['nombre_original']}: TAG/AAD INVÁLIDO (rechazado).")
            continue

        ok += 1
        ruta_out = os.path.join(DIR_RECUPERADOS, datos["nombre_original"])
        with open(ruta_out, "wb") as f:
            f.write(plaintext)

        # Comparación byte a byte y por SHA-256 contra el original.
        ruta_orig = os.path.join(DIR_ORIGINALES, datos["nombre_original"])
        if os.path.exists(ruta_orig):
            with open(ruta_orig, "rb") as f:
                original = f.read()
            igual_bytes = original == plaintext
            igual_hash = (hashlib.sha256(original).hexdigest()
                          == hashlib.sha256(plaintext).hexdigest())
            if igual_bytes and igual_hash:
                iguales += 1
                print(f"   [i={i}] {datos['nombre_original']}: OK, idéntico al original.")
            else:
                print(f"   [i={i}] {datos['nombre_original']}: DIFERENCIA detectada.")
        else:
            print(f"   [i={i}] {datos['nombre_original']}: recuperado "
                  f"(sin original para comparar).")

    _borrar_segura(s_v)
    del s_v
    print(f"[cliente] Paso 6 resumen: {total} procesados | {ok} descifrados | "
          f"{fallos} rechazados | {iguales} idénticos al original.")


# ===========================================================================
def main() -> None:
    ap = argparse.ArgumentParser(description="Cliente/Víctima (Modelo A).")
    ap.add_argument("--modo", choices=["cifrado", "recuperacion_servidor"],
                    default="cifrado")
    ap.add_argument("--host", default=HOST_DEF)
    ap.add_argument("--puerto", type=int, default=PUERTO_DEF)
    args = ap.parse_args()

    if args.modo == "cifrado":
        modo_cifrado(args.host, args.puerto)
    else:
        modo_recuperacion(args.host, args.puerto)


if __name__ == "__main__":
    main()
