"""investigacion_5b.py — Auditoría de entropía / búsqueda de la semilla.

Objetivo pedagógico: demostrar que, aunque s_v se transmite protegida por
RSA-OAEP y los archivos se cifran con AES-256-GCM (primitivas fuertes), la
seguridad REAL del sistema queda acotada por la entropía del generador:

    generador_semillas.py:
        configuracion = secrets.randbelow(9) + 16   # 16..24
        valor = secrets.randbelow(1 << configuracion)
        return valor.to_bytes(32, "big")

Como configuracion <= 24, se cumple siempre valor < 2**24. El espacio efectivo
de semillas es, por tanto, [0, 2**24): solo ~16.7 millones de candidatos,
trivialmente recorribles por fuerza bruta SIN tocar RSA ni romper AES.

Este script NO requiere el servidor en marcha (ataca material ya en disco):

  1. Carga ÚNICAMENTE el .enc.json con contador i=0.
  2. Itera valor de 0 a 2**24-1, deriva K_0 = HMAC-SHA256(valor||..., 0) y prueba
     AESGCM(K_0).decrypt(nonce, ciphertext+tag, aad). El tag GCM actúa como
     oráculo: solo la semilla correcta produce un descifrado válido.
  3. Al encontrarla mide: tiempo total, candidatos evaluados y velocidad.
  4. Con la s_v hallada descifra el resto de archivos, midiendo por separado el
     tiempo de descifrado y el de comparación byte a byte contra los originales.

Uso:
    python investigacion_5b.py
"""

from __future__ import annotations

import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_utils as cu

DIR = os.path.dirname(os.path.abspath(__file__))
DIR_CIFRADOS = os.path.join(DIR, "archivos_cifrados")
DIR_ORIGINALES = os.path.join(DIR, "archivos_originales")
DIR_ATACADOS = os.path.join(DIR, "archivos_atacados")

ESPACIO = 1 << 24  # 2**24, cota superior demostrada del generador


# --------------------------------------------------------------------------- #
def localizar_i0() -> str:
    """Devuelve la ruta del .enc.json cuyo contador_i == 0."""
    for nombre in sorted(os.listdir(DIR_CIFRADOS)):
        if not nombre.endswith(".enc.json"):
            continue
        datos = cu.cargar_enc(os.path.join(DIR_CIFRADOS, nombre))
        if datos["contador_i"] == 0:
            return os.path.join(DIR_CIFRADOS, nombre)
    raise FileNotFoundError("No se encontró ningún .enc.json con contador_i=0.")


def buscar_semilla(datos0: dict) -> tuple[bytes, int, float, float]:
    """Fuerza bruta sobre [0, 2**24) usando el archivo i=0.

    Devuelve (s_v, candidatos_evaluados, tiempo_total, velocidad).
    """
    id_v = datos0["id_v"]
    nonce = datos0["nonce"]
    ct_tag = datos0["ciphertext"] + datos0["tag"]
    aad = cu.construir_aad(id_v, 0)
    msg0 = (0).to_bytes(8, "big")  # para i=0, mensaje HMAC constante

    import hmac as _hmac  # hmac de la stdlib: mucho más rápido en bucle cerrado

    print(f"[5b] Iniciando búsqueda en [0, 2**24) = {ESPACIO:,} candidatos...")
    t0 = time.perf_counter()
    for valor in range(ESPACIO):
        s_cand = valor.to_bytes(32, "big")
        k0 = _hmac.new(s_cand, msg0, hashlib.sha256).digest()
        try:
            AESGCM(k0).decrypt(nonce, ct_tag, aad)
        except Exception:
            continue
        # ¡Tag válido! Semilla encontrada.
        t = time.perf_counter() - t0
        evaluados = valor + 1
        vel = evaluados / t if t > 0 else float("inf")
        return s_cand, evaluados, t, vel

        # (sin break: el return corta el bucle)

    raise RuntimeError("Semilla no encontrada en [0, 2**24): revisa el generador o los datos.")


def descifrar_resto(s_v: bytes) -> None:
    """Con la semilla hallada, descifra todos los archivos y compara."""
    os.makedirs(DIR_ATACADOS, exist_ok=True)
    cifrados = sorted(n for n in os.listdir(DIR_CIFRADOS) if n.endswith(".enc.json"))

    t_descifrado = 0.0
    t_comparacion = 0.0
    total = ok = iguales = 0

    for nombre in cifrados:
        total += 1
        datos = cu.cargar_enc(os.path.join(DIR_CIFRADOS, nombre))
        i = datos["contador_i"]
        aad = cu.construir_aad(datos["id_v"], i)

        t = time.perf_counter()
        k_i = cu.derivar_clave(s_v, i)
        try:
            plaintext = cu.aes_descifrar(k_i, datos["nonce"], datos["ciphertext"],
                                         datos["tag"], aad)
        except cu.InvalidTag:
            t_descifrado += time.perf_counter() - t
            print(f"   [i={i}] {datos['nombre_original']}: tag inválido.")
            continue
        t_descifrado += time.perf_counter() - t
        ok += 1

        with open(os.path.join(DIR_ATACADOS, datos["nombre_original"]), "wb") as f:
            f.write(plaintext)

        ruta_orig = os.path.join(DIR_ORIGINALES, datos["nombre_original"])
        if os.path.exists(ruta_orig):
            t = time.perf_counter()
            with open(ruta_orig, "rb") as f:
                original = f.read()
            igual = (original == plaintext and
                     hashlib.sha256(original).digest() == hashlib.sha256(plaintext).digest())
            t_comparacion += time.perf_counter() - t
            if igual:
                iguales += 1

    print("\n[5b] --- Descifrado masivo con la semilla hallada ---")
    print(f"   Archivos procesados : {total}")
    print(f"   Descifrados OK      : {ok}")
    print(f"   Idénticos al original: {iguales}")
    print(f"   Tiempo de descifrado : {t_descifrado*1000:.2f} ms")
    print(f"   Tiempo de comparación: {t_comparacion*1000:.2f} ms")
    print(f"   Copias en: {DIR_ATACADOS}")


# --------------------------------------------------------------------------- #
def main() -> None:
    print("=" * 70)
    print(" AUDITORÍA DE ENTROPÍA (Punto 5b) — servidor NO requerido")
    print("=" * 70)

    ruta0 = localizar_i0()
    datos0 = cu.cargar_enc(ruta0)
    print(f"[5b] Archivo i=0: {os.path.basename(ruta0)} "
          f"(id_v={datos0['id_v']}, original='{datos0['nombre_original']}')\n")

    s_v, evaluados, t_total, vel = buscar_semilla(datos0)

    print("\n[5b] --- RESULTADO DE LA BÚSQUEDA ---")
    print(f"   Semilla s_v (hex)   : {s_v.hex()}")
    print(f"   Valor entero        : {int.from_bytes(s_v, 'big'):,}")
    print(f"   Candidatos evaluados: {evaluados:,} de {ESPACIO:,}")
    print(f"   Tiempo total        : {t_total:.3f} s")
    print(f"   Velocidad           : {vel:,.0f} candidatos/seg")

    descifrar_resto(s_v)

    print("\n[5b] Conclusión: la fortaleza de RSA-OAEP y AES-GCM es irrelevante")
    print("     si la semilla vive en un espacio de 2**24. La entropía del")
    print("     generador, no el cifrado, es el eslabón débil.")


if __name__ == "__main__":
    main()
