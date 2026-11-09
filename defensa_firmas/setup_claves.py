"""setup_claves.py — Genera las claves Ed25519 y las PRE-COMPARTE en disco.

Ejecutar UNA vez antes de usar la versión defendida. Crea:

  claves_privadas/cliente_firma_sk.pem    (solo lo conoce el cliente)
  claves_privadas/servidor_firma_sk.pem   (solo lo conoce el servidor)
  trusted_keys/cliente_firma_pub.pem      (pre-compartida: la tiene el servidor)
  trusted_keys/servidor_firma_pub.pem     (pre-compartida: la tiene el cliente)

El supuesto de seguridad es que trusted_keys/ se distribuye por un canal fuera
de banda (no por la red interceptable). El intermediario no puede sustituir
estas claves públicas, y por eso no puede falsificar firmas válidas.

Uso:
    python setup_claves.py
"""

from __future__ import annotations

import os

import firma_utils as fu

DIR = os.path.dirname(os.path.abspath(__file__))
PRIV = os.path.join(DIR, "claves_privadas")
TRUST = os.path.join(DIR, "trusted_keys")


def _crear_par(nombre: str) -> None:
    sk = fu.generar_par_firma()
    with open(os.path.join(PRIV, f"{nombre}_firma_sk.pem"), "wb") as f:
        f.write(fu.serializar_priv_firma(sk))
    with open(os.path.join(TRUST, f"{nombre}_firma_pub.pem"), "wb") as f:
        f.write(fu.serializar_pub_firma(sk.public_key()))
    print(f"[setup] Par Ed25519 de '{nombre}': "
          f"privada en claves_privadas/, pública en trusted_keys/.")


def main() -> None:
    os.makedirs(PRIV, exist_ok=True)
    os.makedirs(TRUST, exist_ok=True)
    _crear_par("cliente")
    _crear_par("servidor")
    print("[setup] Claves de confianza generadas y pre-compartidas.")


if __name__ == "__main__":
    main()
