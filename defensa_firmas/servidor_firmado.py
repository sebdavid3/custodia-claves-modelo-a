"""servidor_firmado.py — Servidor con defensa por firmas Ed25519 (Modelo A).

Idéntico en función a ../servidor.py, pero AUTENTICA cada paso crítico:

  * REGISTRO: verifica la firma del cliente sobre (id_v || pk_v || 'cliente')
    con la clave de confianza trusted_keys/cliente_firma_pub.pem. Si la firma
    no valida o no procede de la clave de confianza, ABORTA y NO genera ni
    envía la semilla.
  * SEMILLA: firma (id_v || s_v_cifrada || 'servidor') para que el cliente
    pueda verificar que el criptograma no fue alterado por un intermediario.

Efecto: si el proxy sustituye pk_v por pk_m en el REGISTRO, la firma del
cliente (hecha sobre pk_v) no cuadra con pk_m y el servidor se detiene antes
de liberar s_v.

Uso:
    python setup_claves.py          # una sola vez
    python servidor_firmado.py --puerto 50000
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu                         # noqa: E402
from generador_semillas import generar_semilla_maestra  # noqa: E402
import firma_utils as fu                          # noqa: E402

DIR = os.path.dirname(os.path.abspath(__file__))
SK_PATH = os.path.join(DIR, "servidor_sk.pem")
PK_PATH = os.path.join(DIR, "servidor_pk.pem")
DB_PATH = os.path.join(DIR, "db_servidor_firmado.json")
FIRMA_SK = os.path.join(DIR, "claves_privadas", "servidor_firma_sk.pem")
CONF_CLIENTE = os.path.join(DIR, "trusted_keys", "cliente_firma_pub.pem")

HOST_DEF, PUERTO_DEF = "127.0.0.1", 50000


def cargar_o_crear_rsa():
    if os.path.exists(SK_PATH):
        with open(SK_PATH, "rb") as f:
            return cu.cargar_privada_pem(f.read())
    sk = cu.generar_par_rsa()
    with open(SK_PATH, "wb") as f:
        f.write(cu.serializar_privada_pem(sk))
    with open(PK_PATH, "wb") as f:
        f.write(cu.serializar_publica_pem(sk.public_key()))
    return sk


def cargar_db():
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"clientes": {}}


def guardar_db(db):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def main() -> None:
    ap = argparse.ArgumentParser(description="Servidor firmado (Modelo A).")
    ap.add_argument("--host", default=HOST_DEF)
    ap.add_argument("--puerto", type=int, default=PUERTO_DEF)
    args = ap.parse_args()

    if not (os.path.exists(FIRMA_SK) and os.path.exists(CONF_CLIENTE)):
        print("[servidor+] Faltan claves de firma. Ejecuta: python setup_claves.py")
        return

    sk = cargar_o_crear_rsa()
    pk_s_pem = cu.serializar_publica_pem(sk.public_key()).decode("ascii")
    firma_sk = fu.cargar_priv_firma(FIRMA_SK)
    conf_cliente = fu.cargar_pub_firma(CONF_CLIENTE)
    db = cargar_db()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.puerto))
        s.listen()
        print(f"[servidor+] Escuchando (con firmas) en {args.host}:{args.puerto}.")
        try:
            while True:
                conn, addr = s.accept()
                print(f"[servidor+] Conexión de {addr}")
                with conn:
                    atender(conn, db, pk_s_pem, firma_sk, conf_cliente)
        except KeyboardInterrupt:
            print("\n[servidor+] Detenido.")


def atender(conn, db, pk_s_pem, firma_sk, conf_cliente):
    while True:
        try:
            msg = cu.recibir_json(conn)
        except (ConnectionError, OSError):
            break
        accion = msg.get("accion")

        if accion == "REGISTRO":
            id_v, pk_v_pem = msg["id_v"], msg["pk_v"]
            firma = base64.b64decode(msg.get("firma", ""))

            # --- Caso 2: si el mensaje ADJUNTA una clave de verificación,
            #     debe coincidir EXACTAMENTE con la pre-compartida en trusted_keys/.
            pk_firma_adj = msg.get("pk_firma_cliente")
            if pk_firma_adj is not None:
                try:
                    adj = fu.cargar_pub_firma_bytes(pk_firma_adj.encode("utf-8"))
                except Exception:
                    adj = None
                if adj is None or not fu.iguales_clave(adj, conf_cliente):
                    print(f"[servidor+] !! Clave de verificación ADJUNTA no coincide "
                          f"con trusted_keys/ para {id_v}. Suplantación (Caso 2): "
                          f"se ABORTA (no se enviará s_v).")
                    cu.enviar_json(conn, {"accion": "ABORTADO",
                                          "detalle": "clave de firma adjunta no confiable"})
                    continue

            # --- Caso 1: la firma debe validar bajo la clave de CONFIANZA ---
            ok = fu.verificar(conf_cliente, firma, id_v,
                              pk_v_pem.encode("utf-8"), "cliente")
            if not ok:
                print(f"[servidor+] !! Firma de REGISTRO INVÁLIDA para {id_v}. "
                      f"Posible MITM (Caso 1): se ABORTA (no se enviará s_v).")
                cu.enviar_json(conn, {"accion": "ABORTADO",
                                      "detalle": "firma de cliente inválida"})
                continue
            if id_v not in db["clientes"]:
                db["clientes"][id_v] = {"pk_v": pk_v_pem, "s_v": None,
                                        "autorizado": False, "entrega_inicial": False}
                guardar_db(db)
            print(f"[servidor+] REGISTRO autenticado de {id_v}.")
            cu.enviar_json(conn, {"accion": "REGISTRO_OK", "pk_s_pem": pk_s_pem})

        elif accion == "SOLICITAR_SEMILLA":
            id_v = msg["id_v"]
            c = db["clientes"].get(id_v)
            if c is None:
                cu.enviar_json(conn, {"accion": "ERROR", "detalle": "no registrado"})
                continue
            if c.get("entrega_inicial"):
                cu.enviar_json(conn, {"accion": "ERROR",
                                      "detalle": "entrega inicial ya realizada; use RECUPERAR"})
                continue
            if c["s_v"] is None:
                s_v = generar_semilla_maestra()
                c["s_v"] = base64.b64encode(s_v).decode("ascii")
            else:
                s_v = base64.b64decode(c["s_v"])
            c["entrega_inicial"] = True
            guardar_db(db)
            pk_v = cu.cargar_publica_pem(c["pk_v"].encode("utf-8"))
            s_v_cif = cu.rsa_cifrar(pk_v, s_v)
            # --- EL SERVIDOR FIRMA EL CRIPTOGRAMA ---
            firma = fu.firmar(firma_sk, id_v, s_v_cif, "servidor")
            cu.enviar_json(conn, {
                "accion": "SEMILLA", "id_v": id_v,
                "s_v_cifrada": base64.b64encode(s_v_cif).decode("ascii"),
                "firma": base64.b64encode(firma).decode("ascii"),
            })
            print(f"[servidor+] SEMILLA firmada enviada a {id_v}.")

        elif accion == "RECUPERAR":
            id_v = msg["id_v"]
            firma = base64.b64decode(msg.get("firma", ""))
            # El cliente firma (id_v || 'RECUPERAR' || 'cliente').
            if not fu.verificar(conf_cliente, firma, id_v, b"RECUPERAR", "cliente"):
                print(f"[servidor+] !! Firma de RECUPERAR inválida para {id_v}. ABORTA.")
                cu.enviar_json(conn, {"accion": "ABORTADO",
                                      "detalle": "firma de recuperación inválida"})
                continue
            c = db["clientes"].get(id_v)
            if c is None or c["s_v"] is None:
                cu.enviar_json(conn, {"accion": "ERROR", "detalle": "sin semilla custodiada"})
                continue
            if not msg.get("evento_autorizacion"):
                cu.enviar_json(conn, {"accion": "DENEGADO",
                                      "detalle": "falta evento de autorización"})
                continue
            c["autorizado"] = True
            guardar_db(db)
            s_v = base64.b64decode(c["s_v"])
            pk_v = cu.cargar_publica_pem(c["pk_v"].encode("utf-8"))   # pk_v del Paso 1
            s_v_cif = cu.rsa_cifrar(pk_v, s_v)
            firma_s = fu.firmar(firma_sk, id_v, s_v_cif, "servidor")
            cu.enviar_json(conn, {
                "accion": "SEMILLA_RECUPERADA", "id_v": id_v,
                "s_v_cifrada": base64.b64encode(s_v_cif).decode("ascii"),
                "firma": base64.b64encode(firma_s).decode("ascii"),
            })
            print(f"[servidor+] RECUPERAR autorizado y firmado para {id_v}.")

        elif accion == "ACK":
            print(f"[servidor+] ACK de {msg['id_v']}.")
            cu.enviar_json(conn, {"accion": "ACK_OK"})

        else:
            cu.enviar_json(conn, {"accion": "ERROR", "detalle": f"acción: {accion}"})


if __name__ == "__main__":
    main()
