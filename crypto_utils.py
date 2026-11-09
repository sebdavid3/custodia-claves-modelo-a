"""crypto_utils.py — Módulo criptográfico común (Actividad III, Modelo A).

Reúne todas las primitivas compartidas por cliente, servidor, proxy y los
scripts de investigación/defensa:

  * RSA-2048  : generación, serialización PEM y cifrado/descifrado RSA-OAEP(SHA-256).
  * Derivación: derivar_clave(s_v, i) = HMAC-SHA256(key=s_v, msg=i.to_bytes(8,'big')).
  * AES-256-GCM: nonce aleatorio de 12 bytes, tag de 16 bytes y AAD determinista.
  * Formato .enc.json: contenedor JSON con los campos en Base64.
  * Framing de sockets TCP: JSON con prefijo de longitud (4 bytes big-endian).

Diseño: ningún material secreto (s_v, K_i) se guarda en disco desde este módulo;
solo se serializan los contenedores cifrados y las claves RSA (la privada del
cliente/servidor, necesaria para persistir la identidad entre ejecuciones).

Procedencia (Colab 1, secciones 7 y 8). Este módulo adapta las operaciones del
cuaderno a la librería `cryptography` y a los flujos del enunciado:
  * RSA-OAEP(SHA-256)  <- sec. 7 (allí PKCS1_OAEP de PyCryptodome).
  * rsa_cifrar/descifrar <- sec. 8.2 (encapsular_oaep/desencapsular_oaep).
  * AES-256-GCM, tag 16 B <- sec. 8.3 (cifrar_simetrico/descifrar_simetrico).
Diferencias deliberadas respecto al Colab se explican en INFORME_BASE.md
(HKDF de sesión -> derivación HMAC por contador; nonce de contador -> nonce
aleatorio; secreto de sesión -> semilla maestra del Modelo A).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature  # noqa: F401 (reexport)

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #
RSA_KEY_SIZE = 2048
NONCE_LEN = 12        # 96 bits, recomendado para AES-GCM
TAG_LEN = 16          # 128 bits
LONGITUD_PREFIJO = 4  # bytes del prefijo de longitud en el framing TCP


# ===========================================================================
# 1. RSA-2048: generación y serialización PEM
# ===========================================================================
def generar_par_rsa() -> rsa.RSAPrivateKey:
    """Genera un par de claves RSA-2048 (exponente público estándar 65537)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def serializar_privada_pem(clave_privada: rsa.RSAPrivateKey) -> bytes:
    """Serializa una clave privada RSA a PEM (PKCS#8, sin cifrar)."""
    return clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serializar_publica_pem(clave_publica: rsa.RSAPublicKey) -> bytes:
    """Serializa una clave pública RSA a PEM (SubjectPublicKeyInfo)."""
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def cargar_privada_pem(pem: bytes) -> rsa.RSAPrivateKey:
    """Carga una clave privada RSA desde bytes PEM."""
    return serialization.load_pem_private_key(pem, password=None)


def cargar_publica_pem(pem: bytes) -> rsa.RSAPublicKey:
    """Carga una clave pública RSA desde bytes PEM."""
    return serialization.load_pem_public_key(pem)


# ===========================================================================
# 2. RSA-OAEP (SHA-256): cifrado / descifrado asimétrico
# ===========================================================================
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def rsa_cifrar(clave_publica: rsa.RSAPublicKey, mensaje: bytes) -> bytes:
    """Cifra `mensaje` con RSA-OAEP(SHA-256). Para RSA-2048 el máximo es 190 bytes."""
    return clave_publica.encrypt(mensaje, _OAEP)


def rsa_descifrar(clave_privada: rsa.RSAPrivateKey, cifrado: bytes) -> bytes:
    """Descifra con RSA-OAEP(SHA-256)."""
    return clave_privada.decrypt(cifrado, _OAEP)


# ===========================================================================
# 3. Derivación de claves: HMAC-SHA256
# ===========================================================================
def derivar_clave(s_v: bytes, i: int) -> bytes:
    """K_i = HMAC-SHA256(key=s_v, msg=i.to_bytes(8,'big')).

    Devuelve 32 bytes aptos como clave AES-256.
    """
    h = hmac.HMAC(s_v, hashes.SHA256())
    h.update(i.to_bytes(8, "big"))
    return h.finalize()


# ===========================================================================
# 4. AES-256-GCM
# ===========================================================================
def construir_aad(id_v: str, i: int) -> bytes:
    """Datos Asociados deterministas: id_v || '|' || i(8 bytes big-endian).

    Ligar id_v y el contador al cifrado impide reutilizar un .enc.json de otra
    víctima o con otro índice sin que la verificación del tag falle.
    """
    return id_v.encode("utf-8") + b"|" + i.to_bytes(8, "big")


def aes_cifrar(clave: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes, bytes]:
    """Cifra con AES-256-GCM. Devuelve (nonce, ciphertext, tag) separados.

    cryptography concatena ciphertext||tag; aquí los separamos para guardarlos
    en campos distintos del contenedor .enc.json.
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(clave)
    ct_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    return nonce, ciphertext, tag


def aes_descifrar(clave: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """Descifra y verifica AES-256-GCM. Lanza InvalidTag si tag o AAD no cuadran."""
    aesgcm = AESGCM(clave)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)


# ===========================================================================
# 5. Formato de archivo cifrado (.enc.json)
# ===========================================================================
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def empaquetar_enc(
    id_v: str,
    contador_i: int,
    nombre_original: str,
    nonce: bytes,
    tag: bytes,
    ciphertext: bytes,
) -> dict:
    """Construye el diccionario del contenedor .enc.json (campos en Base64)."""
    return {
        "id_v": id_v,
        "contador_i": contador_i,
        "nombre_original": nombre_original,
        "nonce": _b64(nonce),
        "tag": _b64(tag),
        "ciphertext": _b64(ciphertext),
    }


def guardar_enc(ruta: str, contenedor: dict) -> None:
    """Escribe el contenedor como JSON legible en disco."""
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(contenedor, f, indent=2, ensure_ascii=False)


def cargar_enc(ruta: str) -> dict:
    """Lee un .enc.json y devuelve nonce/tag/ciphertext ya decodificados a bytes."""
    with open(ruta, "r", encoding="utf-8") as f:
        c = json.load(f)
    return {
        "id_v": c["id_v"],
        "contador_i": c["contador_i"],
        "nombre_original": c["nombre_original"],
        "nonce": _unb64(c["nonce"]),
        "tag": _unb64(c["tag"]),
        "ciphertext": _unb64(c["ciphertext"]),
    }


# ===========================================================================
# 6. Framing de sockets TCP: JSON con prefijo de longitud
# ===========================================================================
def _recv_exacto(sock: socket.socket, n: int) -> bytes:
    """Lee exactamente n bytes del socket o lanza ConnectionError si se cierra."""
    buf = bytearray()
    while len(buf) < n:
        trozo = sock.recv(n - len(buf))
        if not trozo:
            raise ConnectionError("Conexión cerrada por el otro extremo")
        buf.extend(trozo)
    return bytes(buf)


def enviar_json(sock: socket.socket, obj: dict) -> None:
    """Envía un objeto JSON precedido por su longitud (4 bytes big-endian)."""
    datos = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack(">I", len(datos)) + datos)


def recibir_json(sock: socket.socket) -> dict:
    """Recibe un objeto JSON con prefijo de longitud."""
    (longitud,) = struct.unpack(">I", _recv_exacto(sock, LONGITUD_PREFIJO))
    datos = _recv_exacto(sock, longitud)
    return json.loads(datos.decode("utf-8"))
