"""cliente_firmado.py — Cliente con defensa por firmas Ed25519 (Modelo A).

Añade autenticación al protocolo de ../cliente.py y soporta el ciclo completo
(cifrado + reinicio + recuperación autorizada):

  modo cifrado (por defecto):
    * REGISTRO: firma (id_v || pk_v || 'cliente').
    * SEMILLA : verifica la firma del servidor sobre (id_v || s_v_cifrada ||
      'servidor') ANTES de usar s_v. Si no valida, ABORTA.
    * Cifra ../archivos_trabajo/ en archivos_cifrados/ y guarda copia de los
      originales en archivos_originales/ para la comparación.

  modo recuperacion_servidor (--modo recuperacion_servidor):
    * RECUPERAR: firma (id_v || 'RECUPERAR' || 'cliente') y pide s_v.
    * Verifica la firma del servidor sobre el criptograma antes de descifrar.
    * Regenera K_i, verifica tag/AAD, escribe en archivos_recuperados/ y
      compara byte a byte (y SHA-256) contra archivos_originales/.

Si un proxy intenta el MITM:
  - sustituir pk_v -> el servidor rechaza el REGISTRO (Caso 1);
  - forjar firma y adjuntar su clave -> el servidor rechaza (Caso 2);
  - re-cifrar s_v -> el cliente detecta la firma alterada y aborta.

Uso:
    python setup_claves.py                      # una sola vez
    python cliente_firmado.py --puerto 50000
    python cliente_firmado.py --modo recuperacion_servidor --puerto 50000
    python cliente_firmado.py --puerto 60000    # vía proxy (debe fallar)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import socket
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu           # noqa: E402
import firma_utils as fu            # noqa: E402

DIR = os.path.dirname(os.path.abspath(__file__))
PADRE = os.path.dirname(DIR)
SK_PATH = os.path.join(DIR, "cliente_sk.pem")
PK_PATH = os.path.join(DIR, "cliente_pk.pem")
ID_PATH = os.path.join(DIR, "cliente_id.txt")
FIRMA_SK = os.path.join(DIR, "claves_privadas", "cliente_firma_sk.pem")
CONF_SERVIDOR = os.path.join(DIR, "trusted_keys", "servidor_firma_pub.pem")

DIR_TRABAJO = os.path.join(PADRE, "archivos_trabajo")
DIR_CIFRADOS = os.path.join(DIR, "archivos_cifrados")
DIR_ORIGINALES = os.path.join(DIR, "archivos_originales")
DIR_RECUPERADOS = os.path.join(DIR, "archivos_recuperados")

HOST_DEF, PUERTO_DEF = "127.0.0.1", 50000


def cargar_o_crear_identidad():
    if os.path.exists(SK_PATH) and os.path.exists(ID_PATH):
        with open(SK_PATH, "rb") as f:
            sk = cu.cargar_privada_pem(f.read())
        with open(ID_PATH, "r", encoding="utf-8") as f:
            return sk, f.read().strip()
    sk = cu.generar_par_rsa()
    with open(SK_PATH, "wb") as f:
        f.write(cu.serializar_privada_pem(sk))
    with open(PK_PATH, "wb") as f:
        f.write(cu.serializar_publica_pem(sk.public_key()))
    id_v = str(uuid.uuid4())
    with open(ID_PATH, "w", encoding="utf-8") as f:
        f.write(id_v)
    return sk, id_v


def _comprobar_claves_firma() -> bool:
    if not (os.path.exists(FIRMA_SK) and os.path.exists(CONF_SERVIDOR)):
        print("[cliente+] Faltan claves de firma. Ejecuta: python setup_claves.py")
        return False
    return True


# ===========================================================================
def modo_cifrado(host: str, puerto: int) -> None:
    if not _comprobar_claves_firma():
        return
    sk, id_v = cargar_o_crear_identidad()
    pk_v_pem = cu.serializar_publica_pem(sk.public_key()).decode("ascii")
    firma_sk = fu.cargar_priv_firma(FIRMA_SK)
    conf_servidor = fu.cargar_pub_firma(CONF_SERVIDOR)
    print(f"[cliente+] id_v={id_v}")

    with socket.create_connection((host, puerto)) as s:
        # ---- REGISTRO firmado ----
        firma = fu.firmar(firma_sk, id_v, pk_v_pem.encode("utf-8"), "cliente")
        cu.enviar_json(s, {"accion": "REGISTRO", "id_v": id_v, "pk_v": pk_v_pem,
                           "firma": base64.b64encode(firma).decode("ascii")})
        r = cu.recibir_json(s)
        if r.get("accion") != "REGISTRO_OK":
            print(f"[cliente+] Registro rechazado: {r}. "
                  f"(si hay proxy, la defensa lo detuvo -> OK)")
            return
        print("[cliente+] REGISTRO autenticado y aceptado.")

        # ---- SEMILLA firmada ----
        cu.enviar_json(s, {"accion": "SOLICITAR_SEMILLA", "id_v": id_v})
        r = cu.recibir_json(s)
        if r.get("accion") != "SEMILLA":
            print(f"[cliente+] No se recibió semilla: {r}")
            return
        s_v_cif = base64.b64decode(r["s_v_cifrada"])
        firma_s = base64.b64decode(r.get("firma", ""))
        if not fu.verificar(conf_servidor, firma_s, id_v, s_v_cif, "servidor"):
            print("[cliente+] !! Firma del servidor INVÁLIDA sobre s_v_cifrada. "
                  "Posible MITM: se ABORTA sin usar s_v.")
            return
        s_v = bytearray(cu.rsa_descifrar(sk, s_v_cif))
        print(f"[cliente+] s_v autenticada y descifrada ({len(s_v)} bytes).")

        cu.enviar_json(s, {"accion": "ACK", "id_v": id_v})
        cu.recibir_json(s)

    # ---- Cifrado de archivos ----
    os.makedirs(DIR_CIFRADOS, exist_ok=True)
    os.makedirs(DIR_ORIGINALES, exist_ok=True)
    archivos = sorted(n for n in os.listdir(DIR_TRABAJO)
                      if os.path.isfile(os.path.join(DIR_TRABAJO, n))) \
        if os.path.isdir(DIR_TRABAJO) else []
    for i, nombre in enumerate(archivos):
        ruta_in = os.path.join(DIR_TRABAJO, nombre)
        with open(ruta_in, "rb") as f:
            pt = f.read()
        k_i = cu.derivar_clave(bytes(s_v), i)
        aad = cu.construir_aad(id_v, i)
        nonce, ct, tag = cu.aes_cifrar(k_i, pt, aad)
        cu.guardar_enc(os.path.join(DIR_CIFRADOS, f"{i:04d}_{nombre}.enc.json"),
                       cu.empaquetar_enc(id_v, i, nombre, nonce, tag, ct))
        shutil.copy2(ruta_in, os.path.join(DIR_ORIGINALES, nombre))
    print(f"[cliente+] {len(archivos)} archivo(s) cifrado(s) en archivos_cifrados/.")

    for b in range(len(s_v)):
        s_v[b] = 0
    print("[cliente+] s_v borrada de memoria.")


# ===========================================================================
def modo_recuperacion(host: str, puerto: int) -> None:
    if not _comprobar_claves_firma():
        return
    if not (os.path.exists(SK_PATH) and os.path.exists(ID_PATH)):
        print("[cliente+] No hay identidad en disco. Ejecuta primero el modo cifrado.")
        return
    with open(SK_PATH, "rb") as f:
        sk = cu.cargar_privada_pem(f.read())
    with open(ID_PATH, "r", encoding="utf-8") as f:
        id_v = f.read().strip()
    firma_sk = fu.cargar_priv_firma(FIRMA_SK)
    conf_servidor = fu.cargar_pub_firma(CONF_SERVIDOR)
    print(f"[cliente+] Recuperación: id_v={id_v} y sk_v cargados.")

    with socket.create_connection((host, puerto)) as s:
        firma = fu.firmar(firma_sk, id_v, b"RECUPERAR", "cliente")
        cu.enviar_json(s, {"accion": "RECUPERAR", "id_v": id_v,
                           "evento_autorizacion": True,
                           "firma": base64.b64encode(firma).decode("ascii")})
        r = cu.recibir_json(s)
        if r.get("accion") != "SEMILLA_RECUPERADA":
            print(f"[cliente+] Recuperación no autorizada / error: {r}")
            return
        s_v_cif = base64.b64decode(r["s_v_cifrada"])
        firma_s = base64.b64decode(r.get("firma", ""))
        if not fu.verificar(conf_servidor, firma_s, id_v, s_v_cif, "servidor"):
            print("[cliente+] !! Firma del servidor INVÁLIDA en recuperación. ABORTA.")
            return
        s_v = bytearray(cu.rsa_descifrar(sk, s_v_cif))
        print(f"[cliente+] s_v recuperada y autenticada ({len(s_v)} bytes).")

    # ---- Descifrado + comparación ----
    os.makedirs(DIR_RECUPERADOS, exist_ok=True)
    cifrados = sorted(n for n in os.listdir(DIR_CIFRADOS) if n.endswith(".enc.json")) \
        if os.path.isdir(DIR_CIFRADOS) else []
    total = ok = iguales = fallos = 0
    for nombre_enc in cifrados:
        total += 1
        datos = cu.cargar_enc(os.path.join(DIR_CIFRADOS, nombre_enc))
        i = datos["contador_i"]
        k_i = cu.derivar_clave(bytes(s_v), i)
        aad = cu.construir_aad(datos["id_v"], i)
        try:
            pt = cu.aes_descifrar(k_i, datos["nonce"], datos["ciphertext"],
                                  datos["tag"], aad)
        except cu.InvalidTag:
            fallos += 1
            print(f"   [i={i}] {datos['nombre_original']}: tag/AAD inválido.")
            continue
        ok += 1
        with open(os.path.join(DIR_RECUPERADOS, datos["nombre_original"]), "wb") as f:
            f.write(pt)
        ruta_orig = os.path.join(DIR_ORIGINALES, datos["nombre_original"])
        if os.path.exists(ruta_orig):
            with open(ruta_orig, "rb") as f:
                original = f.read()
            if original == pt and hashlib.sha256(original).digest() == hashlib.sha256(pt).digest():
                iguales += 1
                print(f"   [i={i}] {datos['nombre_original']}: OK, idéntico al original.")
            else:
                print(f"   [i={i}] {datos['nombre_original']}: DIFERENCIA.")
    for b in range(len(s_v)):
        s_v[b] = 0
    print(f"[cliente+] Recuperación: {total} procesados | {ok} descifrados | "
          f"{fallos} rechazados | {iguales} idénticos.")


# ===========================================================================
def main() -> None:
    ap = argparse.ArgumentParser(description="Cliente firmado (Modelo A).")
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
