"""firma_utils.py — Utilidades de firma digital Ed25519 para la defensa.

La defensa frente al MITM se basa en autenticar el ORIGEN de cada clave/mensaje
crítico. Se firma siempre el trío determinista:

        mensaje_a_firmar = id_v || b'|' || pk_cifrado || b'|' || rol

donde:
  * id_v        : identificador de la víctima (bytes UTF-8).
  * pk_cifrado  : el material que viaja en claro en ese paso
                  - en REGISTRO es la pk_v del cliente (PEM),
                  - en SEMILLA es el criptograma OAEP de s_v.
  * rol         : b'cliente' o b'servidor'.

Las claves públicas de verificación están PRE-COMPARTIDAS en disco (trusted_keys/)
y NO viajan por la red, de modo que un intermediario no puede sustituirlas. Si
altera pk_v o re-cifra s_v, la firma deja de validar y el protocolo se detiene
ANTES de entregar la semilla.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SEP = b"|"


# --------------------------------------------------------------------------- #
# Generación y serialización de claves Ed25519
# --------------------------------------------------------------------------- #
def generar_par_firma() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def serializar_priv_firma(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serializar_pub_firma(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def cargar_priv_firma(ruta: str) -> Ed25519PrivateKey:
    with open(ruta, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cargar_pub_firma(ruta: str) -> Ed25519PublicKey:
    with open(ruta, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def cargar_pub_firma_bytes(pem: bytes) -> Ed25519PublicKey:
    """Carga una clave pública Ed25519 directamente desde bytes PEM (no fichero)."""
    return serialization.load_pem_public_key(pem)


# --------------------------------------------------------------------------- #
# Construcción del mensaje, firma y verificación
# --------------------------------------------------------------------------- #
def construir_mensaje(id_v: str, pk_cifrado: bytes, rol: str) -> bytes:
    """Serialización determinista de (id_v || pk_cifrado || rol)."""
    return id_v.encode("utf-8") + SEP + pk_cifrado + SEP + rol.encode("utf-8")


def firmar(sk: Ed25519PrivateKey, id_v: str, pk_cifrado: bytes, rol: str) -> bytes:
    return sk.sign(construir_mensaje(id_v, pk_cifrado, rol))


def verificar(pk_confianza: Ed25519PublicKey, firma: bytes,
              id_v: str, pk_cifrado: bytes, rol: str) -> bool:
    """True si la firma valida bajo la clave de confianza. No lanza excepción."""
    try:
        pk_confianza.verify(firma, construir_mensaje(id_v, pk_cifrado, rol))
        return True
    except InvalidSignature:
        return False


def iguales_clave(pk_a: Ed25519PublicKey, pk_b: Ed25519PublicKey) -> bool:
    """Compara dos claves públicas Ed25519 por sus bytes canónicos."""
    return serializar_pub_firma(pk_a) == serializar_pub_firma(pk_b)
