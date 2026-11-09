"""proxy_mitm.py — Proxy intermediario (ataque Man-in-the-Middle, Modelo A).

Demostración académica del ataque que el esquema SIN autenticación no puede
evitar. El proxy se interpone entre el cliente y el servidor:

  * Escucha en el puerto donde el cliente cree que está el servidor y reenvía
    al puerto real del servidor (store-and-forward por mensaje).
  * Paso 1: sustituye pk_v por pk_m en el REGISTRO. El servidor acaba
    custodiando pk_m creyendo que es la clave de la víctima.
  * Paso 2: la s_v llega cifrada con pk_m; el proxy la descifra con sk_m,
    guarda s_v interceptada y la RE-CIFRA con la pk_v real para reenviarla al
    cliente, que completa el cifrado sin notar nada anómalo.
  * Con s_v el proxy puede descifrar una copia de los .enc.json de la víctima.

Modos de ataque contra la versión firmada (defensa_firmas/):
  * (por defecto) Caso 1: sustituye pk_v por pk_m pero NO toca la firma del
    cliente. El servidor firmado recomputa la firma sobre pk_m y falla la
    verificación criptográfica -> ABORTA.
  * --modo-suplantacion-firma  Caso 2: el proxy genera su PROPIO par Ed25519,
    firma (id_v || pk_m || 'cliente') y adjunta su clave de verificación en el
    JSON. El servidor firmado lo rechaza porque solo confía en trusted_keys/:
    la clave adjunta no coincide con la pre-compartida (y la firma tampoco
    valida bajo la de confianza).

Uso:
    # Ataque al esquema base
    python servidor.py --puerto 50000
    python proxy_mitm.py --escucha 60000 --servidor-puerto 50000
    python cliente.py --puerto 60000
    python proxy_mitm.py --descifrar

    # Ataque Caso 2 contra la defensa
    python proxy_mitm.py --escucha 60000 --servidor-puerto 50000 --modo-suplantacion-firma
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys

import crypto_utils as cu

DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("CRIPTO_DATA", DIR)   # raíz de datos (parametrizable en contenedores)

# firma_utils vive en defensa_firmas/ y lo usamos para el Caso 2
sys.path.insert(0, os.path.join(DIR, "defensa_firmas"))
import firma_utils as fu   # noqa: E402

BOTIN = os.path.join(BASE, "proxy_botin")
MK_SK = os.path.join(BOTIN, "proxy_sk.pem")
MK_PK = os.path.join(BOTIN, "proxy_pk.pem")
FIRMA_SK = os.path.join(BOTIN, "proxy_firma_sk.pem")   # Ed25519 falso (Caso 2)
MAPA = os.path.join(BOTIN, "mapa_pk_v.json")
SEMILLAS = os.path.join(BOTIN, "semillas_robadas.json")
DIR_CIFRADOS = os.path.join(BASE, "archivos_cifrados")
DIR_BOTIN_ARCH = os.path.join(BOTIN, "archivos_descifrados")


# --------------------------------------------------------------------------- #
def cargar_o_crear_mk():
    os.makedirs(BOTIN, exist_ok=True)
    if os.path.exists(MK_SK):
        with open(MK_SK, "rb") as f:
            return cu.cargar_privada_pem(f.read())
    sk = cu.generar_par_rsa()
    with open(MK_SK, "wb") as f:
        f.write(cu.serializar_privada_pem(sk))
    with open(MK_PK, "wb") as f:
        f.write(cu.serializar_publica_pem(sk.public_key()))
    return sk


def cargar_o_crear_firma_mk():
    """Par Ed25519 propio del atacante para el Caso 2 (suplantación de firma)."""
    os.makedirs(BOTIN, exist_ok=True)
    if os.path.exists(FIRMA_SK):
        return fu.cargar_priv_firma(FIRMA_SK)
    sk = fu.generar_par_firma()
    with open(FIRMA_SK, "wb") as f:
        f.write(fu.serializar_priv_firma(sk))
    return sk


def _cargar_json(ruta: str) -> dict:
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _guardar_json(ruta: str, obj: dict) -> None:
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
def transformar_cliente_a_servidor(msg, sk_m, pk_m_pem, suplantar, firma_mk):
    """Mensajes del cliente hacia el servidor."""
    if msg.get("accion") == "REGISTRO":
        mapa = _cargar_json(MAPA)
        mapa[msg["id_v"]] = msg["pk_v"]          # guardamos la pk_v REAL
        _guardar_json(MAPA, mapa)
        msg = dict(msg)
        msg["pk_v"] = pk_m_pem                    # el servidor custodiará pk_m
        print(f"[MITM] REGISTRO de {msg['id_v']}: pk_v -> pk_m (sustituida).")

        if suplantar:
            # Caso 2: el atacante forja una firma con SU clave y la adjunta.
            firma = fu.firmar(firma_mk, msg["id_v"], pk_m_pem.encode("utf-8"), "cliente")
            pk_firma_adj = fu.serializar_pub_firma(firma_mk.public_key()).decode("ascii")
            msg["firma"] = base64.b64encode(firma).decode("ascii")
            msg["pk_firma_cliente"] = pk_firma_adj
            print("[MITM] Caso 2: firma forjada con clave Ed25519 propia y "
                  "clave de verificación adjunta.")
    return msg


def transformar_servidor_a_cliente(msg, sk_m):
    """Mensajes del servidor hacia el cliente."""
    if msg.get("accion") in ("SEMILLA", "SEMILLA_RECUPERADA"):
        id_v = msg["id_v"]
        s_v_cif_m = base64.b64decode(msg["s_v_cifrada"])
        s_v = cu.rsa_descifrar(sk_m, s_v_cif_m)   # el servidor usó pk_m
        robadas = _cargar_json(SEMILLAS)
        robadas[id_v] = s_v.hex()
        _guardar_json(SEMILLAS, robadas)
        print(f"[MITM] *** s_v INTERCEPTADA para {id_v}: {s_v.hex()}")

        mapa = _cargar_json(MAPA)
        pk_v_pem = mapa.get(id_v)
        if pk_v_pem is None:
            print("[MITM] No tengo pk_v real; el cliente detectaría el fallo.")
            return msg
        pk_v = cu.cargar_publica_pem(pk_v_pem.encode("utf-8"))
        s_v_cif_v = cu.rsa_cifrar(pk_v, s_v)      # re-cifrada para la víctima
        msg = dict(msg)
        msg["s_v_cifrada"] = base64.b64encode(s_v_cif_v).decode("ascii")
        print("[MITM] s_v re-cifrada con pk_v real: el cliente no nota nada.")
    elif msg.get("accion") == "ABORTADO":
        print(f"[MITM] El servidor ABORTÓ: {msg.get('detalle')}. Ataque frustrado.")
    return msg


def atender(cli, host_s, puerto_s, sk_m, pk_m_pem, suplantar, firma_mk):
    with socket.create_connection((host_s, puerto_s)) as srv:
        while True:
            try:
                msg_c = cu.recibir_json(cli)
            except (ConnectionError, OSError):
                break
            cu.enviar_json(srv, transformar_cliente_a_servidor(
                msg_c, sk_m, pk_m_pem, suplantar, firma_mk))
            try:
                msg_s = cu.recibir_json(srv)
            except (ConnectionError, OSError):
                break
            cu.enviar_json(cli, transformar_servidor_a_cliente(msg_s, sk_m))


def modo_descifrar() -> None:
    """Usa las semillas robadas para descifrar una copia de los archivos."""
    robadas = _cargar_json(SEMILLAS)
    if not robadas:
        print("[MITM] No hay semillas robadas todavía.")
        return
    os.makedirs(DIR_BOTIN_ARCH, exist_ok=True)
    cifrados = sorted(n for n in os.listdir(DIR_CIFRADOS) if n.endswith(".enc.json"))
    for id_v, s_hex in robadas.items():
        s_v = bytes.fromhex(s_hex)
        print(f"[MITM] Descifrando botín de {id_v} con s_v={s_hex}")
        for nombre in cifrados:
            datos = cu.cargar_enc(os.path.join(DIR_CIFRADOS, nombre))
            if datos["id_v"] != id_v:
                continue
            i = datos["contador_i"]
            k_i = cu.derivar_clave(s_v, i)
            aad = cu.construir_aad(id_v, i)
            try:
                pt = cu.aes_descifrar(k_i, datos["nonce"], datos["ciphertext"],
                                      datos["tag"], aad)
            except cu.InvalidTag:
                print(f"   [i={i}] tag inválido.")
                continue
            with open(os.path.join(DIR_BOTIN_ARCH, datos["nombre_original"]), "wb") as f:
                f.write(pt)
            print(f"   [i={i}] {datos['nombre_original']} descifrado -> proxy_botin/")


def main() -> None:
    ap = argparse.ArgumentParser(description="Proxy MITM (Modelo A).")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="interfaz de escucha (0.0.0.0 en contenedores)")
    ap.add_argument("--escucha", type=int, default=60000,
                    help="puerto donde escucha el proxy (al que apunta el cliente)")
    ap.add_argument("--servidor-host", default="127.0.0.1")
    ap.add_argument("--servidor-puerto", type=int, default=50000)
    ap.add_argument("--modo-suplantacion-firma", action="store_true",
                    help="Caso 2: forja firma con clave propia y la adjunta")
    ap.add_argument("--descifrar", action="store_true",
                    help="solo descifra el botín con las semillas robadas")
    args = ap.parse_args()

    if args.descifrar:
        modo_descifrar()
        return

    sk_m = cargar_o_crear_mk()
    pk_m_pem = cu.serializar_publica_pem(sk_m.public_key()).decode("ascii")
    firma_mk = cargar_o_crear_firma_mk() if args.modo_suplantacion_firma else None

    etiqueta = "Caso 2 (suplantación de firma)" if args.modo_suplantacion_firma \
        else "Caso 1 (sustitución de pk_v)"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.bind, args.escucha))
        s.listen()
        print(f"[MITM] {etiqueta}")
        print(f"[MITM] Escuchando en {args.bind}:{args.escucha} -> "
              f"{args.servidor_host}:{args.servidor_puerto}")
        try:
            while True:
                cli, addr = s.accept()
                print(f"[MITM] Cliente {addr} conectado.")
                with cli:
                    atender(cli, args.servidor_host, args.servidor_puerto,
                            sk_m, pk_m_pem, args.modo_suplantacion_firma, firma_mk)
                print("[MITM] Sesión terminada. (usa --descifrar para el botín)")
        except KeyboardInterrupt:
            print("\n[MITM] Detenido.")


if __name__ == "__main__":
    main()
