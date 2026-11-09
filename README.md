# Actividad III — Custodia de Claves, Cifrado Híbrido y Autenticación (Modelo A)

Proyecto académico de criptografía con la biblioteca `cryptography`. En el
**Modelo A**, el **servidor** genera la semilla maestra `s_v` y la envía
**cifrada** al cliente. El cliente deriva claves por archivo, cifra con
AES-256-GCM, y más tarde recupera `s_v` del servidor (custodia / *key escrow*).

Incluye además el **ataque** (fuerza bruta de entropía y proxy MITM) y la
**defensa** (firmas digitales Ed25519), que son parte del trabajo.

## Requisitos

```bash
python -m pip install cryptography
```

Probado con Python 3.14 y `cryptography` 50.x (funciona desde 3.10 / 3.x).

## Estructura

| Archivo | Rol |
|---|---|
| `crypto_utils.py` | Módulo común: RSA-2048 PEM, RSA-OAEP(SHA-256), `derivar_clave` (HMAC-SHA256), AES-256-GCM, formato `.enc.json`, framing TCP. |
| `generador_semillas.py` | Generador suministrado (entropía acotada a `[0, 2²⁴)`). **No se modifica.** |
| `servidor.py` | Servidor de custodia (Pasos 1, 2, 5a). |
| `cliente.py` | Cliente/víctima: modo `cifrado` (Pasos 1–3) y `recuperacion_servidor` (Pasos 4–6). |
| `investigacion_5b.py` | Auditoría de entropía: fuerza bruta de `s_v` (servidor apagado). |
| `proxy_mitm.py` | Proxy intermediario MITM (Caso 1 y `--modo-suplantacion-firma` para Caso 2). |
| `defensa_firmas/` | Versión defendida con firmas Ed25519 (incluye recuperación firmada). |
| `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh` | Laboratorio en contenedores sobre red interna. |
| `ejecutar_pruebas.sh` | Genera las 4 evidencias en `evidencias/`. |
| `INFORME_BASE.md` | Informe técnico (diagrama, análisis de entropía, decisiones de firmas, relación con el Colab 1). |

Carpetas de trabajo (se crean solas): `archivos_trabajo/` (entrada),
`archivos_cifrados/` (`.enc.json`), `archivos_originales/` (copia para
comparar), `archivos_recuperados/` (salida del Paso 6).

---

## Diseño criptográfico (resumen)

- **Transporte de la semilla:** RSA-OAEP con SHA-256 sobre RSA-2048.
- **Derivación:** `K_i = HMAC-SHA256(key=s_v, msg=i.to_bytes(8,'big'))` → 32 bytes.
- **Cifrado de archivos:** AES-256-GCM, nonce aleatorio de 12 B, tag de 16 B.
- **AAD determinista:** `id_v.encode('utf-8') + b'|' + i.to_bytes(8,'big')`.
  Liga cada criptograma a su `id_v` y contador: el tag GCM falla si se altera
  cualquiera de los dos.
- **Secretos en RAM:** el cliente nunca escribe `s_v`, las `K_i` ni el mensaje
  OAEP inicial en disco; los borra de memoria tras usarlos.

---

## Uso — flujo principal (A)

Coloca tus archivos en `archivos_trabajo/` (hay ejemplos incluidos).

**Terminal 1 — servidor:**
```bash
python servidor.py --puerto 50000
```

**Terminal 2 — cifrado (Pasos 1, 2, 3):**
```bash
python cliente.py --puerto 50000
```

**Terminal 2 — recuperación autorizada y comparación (Pasos 4, 5a, 6):**
```bash
python cliente.py --modo recuperacion_servidor --puerto 50000
```

El Paso 6 descifra, verifica tag/AAD y compara byte a byte (y por SHA-256)
contra `archivos_originales/`.

---

## Punto 5b — Auditoría de entropía (servidor APAGADO)

Tras haber cifrado al menos una vez (debe existir el `.enc.json` con `i=0`):

```bash
python investigacion_5b.py
```

Recorre `[0, 2²⁴)`, deriva `K_0` por candidato y usa el tag GCM como oráculo.
Imprime tiempo total, candidatos evaluados, velocidad (cand/seg) y luego
descifra el resto midiendo descifrado y comparación por separado.

> **Conclusión:** RSA-OAEP y AES-GCM son fuertes, pero la seguridad real queda
> acotada por la entropía del generador. Con `s_v ∈ [0, 2²⁴)` la semilla se
> encuentra por fuerza bruta en segundos, sin atacar RSA ni AES.

---

## Punto 4 — Proxy MITM (ataque) y defensa con firmas

### Ataque (sin autenticación)

```bash
# 1) Servidor real
python servidor.py --puerto 50000
# 2) Proxy: escucha en 60000 y reenvía a 50000
python proxy_mitm.py --escucha 60000 --servidor-puerto 50000
# 3) El cliente apunta al PROXY
python cliente.py --puerto 60000
# 4) Botín: descifrar copia con la s_v interceptada
python proxy_mitm.py --descifrar
```

El proxy sustituye `pk_v` por `pk_m` (Paso 1), descifra `s_v` con `sk_m`
(Paso 2), la re-cifra con la `pk_v` real y la reenvía: el cliente **no nota
nada** y el proxy se queda con la semilla.

> Para una demostración limpia, parte de estado nuevo (sin `db_servidor.json`
> ni identidad de cliente previos), porque el servidor no sobrescribe registros.

### Defensa (firmas Ed25519)

```bash
cd defensa_firmas
python setup_claves.py                       # una sola vez: claves pre-compartidas
python servidor_firmado.py --puerto 50000    # terminal 1

# Conexión directa -> funciona:
python cliente_firmado.py --puerto 50000     # terminal 2

# A través del proxy -> la defensa lo DETIENE antes de enviar s_v:
#   (proxy en otra terminal)  python ../proxy_mitm.py --escucha 60000 --servidor-puerto 50000
python cliente_firmado.py --puerto 60000
```

Se firma `(id_v || pk_cifrado || rol)` con Ed25519 y se verifica contra las
claves públicas pre-compartidas en `defensa_firmas/trusted_keys/`:

- El **servidor** verifica la firma del cliente sobre `pk_v` en el REGISTRO.
  Si el proxy la sustituye por `pk_m`, la firma no cuadra y **aborta antes de
  generar/enviar `s_v`**.
- El **cliente** verifica la firma del servidor sobre el criptograma de `s_v`.
  Si el proxy lo re-cifra, la firma falla y el cliente **aborta sin usar `s_v`**.

---

## Verificación realizada

| Prueba | Resultado |
|---|---|
| Cifrado + recuperación | 3/3 archivos idénticos al original (bytes y SHA-256) |
| 5b fuerza bruta | semilla hallada; ~10⁵ candidatos/seg |
| Proxy MITM (sin defensa) | `s_v` interceptada; botín descifrado |
| Defensa Ed25519 vía proxy | protocolo abortado; semilla **no** robada |

## Preparar los archivos de trabajo

Coloca los archivos a cifrar en `archivos_trabajo/` (se incluyen 3 de ejemplo).
El cliente les asigna los contadores `i = 0,1,2,…` en orden alfabético y guarda
una copia de cada original en `archivos_originales/` para la comparación del
Paso 6. Para usar los tuyos:

```bash
rm -f archivos_trabajo/*          # opcional: quitar los de ejemplo
cp /ruta/a/tus/archivos/* archivos_trabajo/
```

## Generar todas las evidencias de una vez

```bash
bash ejecutar_pruebas.sh
```

Ejecuta las 4 pruebas y guarda los logs en `evidencias/` para adjuntarlos al
informe. En Windows se corre con Git Bash (usa `powershell.exe` para liberar los
puertos entre pruebas). **Separación de datos:** el script limpia el estado
generado (`db_servidor.json`, claves, `archivos_cifrados/`, `proxy_botin/`, …)
antes de cada prueba, de modo que la vía de investigación (5b) no recibe pistas
de la de pago y la demo MITM parte de una víctima nueva. Cada prueba deja su
estado para inspección hasta que empieza la siguiente.

> **Entrega inicial única:** el servidor entrega `s_v` una sola vez; un segundo
> intento de cifrado se rechaza y obliga a usar la recuperación por pago
> (`--modo recuperacion_servidor`). Por eso el script parte de estado limpio.

## Informe (entrega)

El informe final está en **LaTeX**: `informe.tex` (fuente) e `informe.pdf`
(compilado, con portada, diagramas de secuencia en TikZ y fórmulas nativas).
Para recompilarlo con MiKTeX/TeX Live:

```bash
latexmk -pdf informe.tex
```

`INFORME_BASE.md` se conserva como borrador en Markdown con el mismo contenido.

## Contenedores (opcional)

Con Docker Desktop en marcha:

```bash
docker compose build
docker compose up -d servidor
docker compose run --rm cliente python cliente.py --host servidor --puerto 50000
```

Servidor, proxy y cliente quedan aislados en una red interna, cada uno con su
volumen de datos. Parámetros por variables: `SRV_HOST`, `SRV_PORT`, `PROXY_PORT`.

## Relación con el Colab 1

Las operaciones de RSA-OAEP (§7) y la aplicación cliente-servidor (§8) del Colab
se adaptaron a la librería `cryptography` y a los flujos del enunciado. El detalle
de **qué se usó y qué se modificó** está en [`INFORME_BASE.md`](INFORME_BASE.md),
sección 3.

## Nota de seguridad

Código con fines **educativos**. El borrado de secretos en RAM es *best-effort*
(Python no garantiza *zeroization*); la distribución de `trusted_keys/` asume un
canal fuera de banda; no usar en producción tal cual.
