# Informe Técnico — Actividad III
## Custodia de Claves, Cifrado Híbrido y Autenticación (Modelo A)

> Borrador listo para exportar a PDF (p. ej. `pandoc INFORME_BASE.md -o informe.pdf`,
> o desde VS Code con *Markdown PDF*; los diagramas Mermaid se renderizan en GitHub,
> Obsidian, Typora o con `mermaid-cli`).

---

## 1. Resumen

Se implementa el **Modelo A** del esquema de custodia de claves (*key escrow*):
el **servidor** genera la semilla maestra `s_v`, la entrega al cliente **cifrada
con RSA-OAEP(SHA-256)**, y el cliente deriva una clave por archivo con
**HMAC-SHA256** para cifrarlos con **AES-256-GCM**. Más tarde, el cliente puede
reiniciarse (olvida `s_v`) y **recuperarla** del servidor mediante un evento de
autorización.

Sobre esa base se estudian dos ataques y una defensa:

1. **Auditoría de entropía (5b).** El generador suministrado produce semillas en
   un espacio efectivo de `[0, 2²⁴)`; se recuperan por fuerza bruta en segundos.
2. **Proxy MITM.** Un intermediario sustituye la clave pública del cliente y
   roba `s_v`, porque TCP no autentica el origen de las claves.
3. **Defensa con firmas Ed25519.** Autenticando cada paso contra claves de
   confianza pre-compartidas, el protocolo se **detiene antes de liberar `s_v`**.

Todas las afirmaciones están respaldadas por los logs de `evidencias/`.

---

## 2. Arquitectura y componentes

| Módulo | Función |
|---|---|
| `crypto_utils.py` | RSA-2048/PEM, RSA-OAEP(SHA-256), `derivar_clave` (HMAC-SHA256), AES-256-GCM, formato `.enc.json`, framing TCP. |
| `generador_semillas.py` | Generador **suministrado** (no modificado); entropía acotada. |
| `servidor.py` / `cliente.py` | Protocolo base por sockets (Pasos 1–6). |
| `investigacion_5b.py` | Fuerza bruta de `s_v` (servidor apagado). |
| `proxy_mitm.py` | Ataque MITM (Caso 1 y Caso 2). |
| `defensa_firmas/` | Versión autenticada con Ed25519. |
| `Dockerfile`, `docker-compose.yml` | Aislamiento en contenedores sobre red interna. |
| `ejecutar_pruebas.sh` | Genera las evidencias en `evidencias/`. |

**Primitivas (todas con la librería `cryptography`):**

- Transporte del secreto: `RSA-OAEP` con `MGF1(SHA-256)` y `SHA-256`, sobre RSA-2048.
- Derivación por archivo: `K_i = HMAC-SHA256(key = s_v, msg = i.to_bytes(8,'big'))`.
- Cifrado: `AES-256-GCM`, nonce aleatorio de 12 B, tag de 16 B.
- AAD determinista: `id_v.encode('utf-8') + b'|' + i.to_bytes(8,'big')`.

### 2.1. Notas de conformidad con el enunciado

- **Vía de pago (Paso 5a).** El "evento de pago" del enunciado se implementa como
  el campo `evento_autorizacion=True` del mensaje `RECUPERAR` (no hay dinero real;
  es un evento del protocolo). El modo del cliente se llama `recuperacion_servidor`.
- **Entrega inicial única (Paso 1).** El servidor marca `entrega_inicial=True` tras
  la primera entrega de `s_v`. Repetir el registro **no crea otra maestra** ni
  **habilita una segunda entrega inicial**: una segunda `SOLICITAR_SEMILLA` se
  rechaza y obliga a usar la vía de pago (`RECUPERAR`).
- **`id_V` persistente.** Un único incidente por víctima; `id_v` se conserva en
  disco y acompaña a los mensajes del protocolo.

---

## 3. Relación con el **Colab 1** (qué se usó y qué se modificó)

El proyecto se apoya en el *Colab 1: RSA, fundamentos, ataques y cifrado híbrido*,
en particular **§7 (RSA-OAEP)** y **§8 (aplicación cliente-servidor)**. Dado que
el enunciado exige la librería `cryptography` y flujos distintos (semilla maestra,
derivación por contador, recuperación), las operaciones del Colab se **adaptaron**;
no se copiaron literalmente.

### 3.1. Correspondencia directa (qué se utilizó)

| Concepto del Colab | Dónde (Colab) | Equivalente en el proyecto |
|---|---|---|
| RSA-OAEP con SHA-256 | §7.5 `PKCS1_OAEP.new(..., hashAlgo=SHA256)` | `crypto_utils.rsa_cifrar/rsa_descifrar` con `padding.OAEP(MGF1(SHA256), SHA256)` |
| KEM: cifrar un secreto aleatorio | §8.2 `encapsular_oaep(pk)` → `(C_S, S)` | Paso 2 (Modelo A): el servidor cifra `s_v` con `OAEP(pk_v, s_v)` |
| Recuperar el secreto | §8.2 `desencapsular_oaep(sk, C)` | Cliente: `rsa_descifrar(sk_v, s_v_cifrada)` |
| AES-GCM con tag de 16 B | §8.3 `cifrar_simetrico(clave, datos, contador)` | `crypto_utils.aes_cifrar/aes_descifrar` (`AESGCM`, `mac_len`=16) |
| Contador ligado al AEAD | §8.3 (contador anti-repetición) | AAD `= id_v || i` liga identidad **y** contador al criptograma |
| Alice = servidor, Bob = cliente; una conexión por cliente | §8.1, §8.7–8.8 `atender_cliente`, aceptación por conexión | `servidor.py` acepta y atiende conexiones; `cliente.py` como Bob |
| Advertencia: *TCP no autentica la clave pública* | §1.1 y §8.1 | Motiva directamente el ataque MITM y la defensa con firmas |

### 3.2. Modificaciones (qué se cambió y por qué)

| Aspecto | Colab 1 | Proyecto (Modelo A) | Motivo |
|---|---|---|---|
| Librería | PyCryptodome (`Crypto.*`) | `cryptography` | Requisito del enunciado |
| Secreto transportado | Clave de **sesión** aleatoria `S` | **Semilla maestra** `s_v` del generador suministrado | El Modelo A y el ataque 5b exigen la semilla acotada |
| Derivación de clave | **HKDF**(S, sal, contexto) → una clave de sesión | **HMAC-SHA256**(s_v, i) → **una clave por archivo `K_i`** | El enunciado fija `derivar_clave`; permite recuperar cada archivo por su índice |
| Nonce AES-GCM | Derivado del **contador** | **Aleatorio de 12 B**, guardado en el `.enc.json` | Evita por diseño la reutilización de nonce entre archivos |
| Datos asociados | Contador (anti-repetición en la sesión) | `id_v \|\| i` | Liga cada criptograma a su víctima **y** a su índice |
| Persistencia | En memoria dentro de la sesión | Contenedor `.enc.json`, base de custodia, flujo de recuperación | Requisitos de escrow y de reinicio/recuperación |
| Autenticación | Se **supone** establecida (§1.1) | Se **implementa** con Ed25519 y `trusted_keys/` | Convertir la advertencia del Colab en defensa concreta |

En síntesis: del Colab se conservan **el cifrado híbrido (OAEP para el secreto +
AES-GCM para los datos)** y **la arquitectura cliente-servidor**; se modifican la
librería, la naturaleza del secreto (semilla maestra), la derivación (por archivo),
el manejo del nonce y la persistencia, y se **añade** la capa de autenticación que
el Colab deja como supuesto.

---

## 4. Flujos del protocolo (Modelo A) y punto de rechazo

### 4.1. Diagrama de secuencia — versión **autenticada** (defensa_firmas)

```mermaid
sequenceDiagram
    autonumber
    participant C as Cliente (Bob)
    participant M as Proxy MITM
    participant S as Servidor (Alice)

    note over C,S: Claves de verificación Ed25519 pre-compartidas en trusted_keys/

    rect rgb(235,245,255)
    note over C,S: Paso 1 — REGISTRO (autenticado)
    C->>M: REGISTRO { id_v, pk_v, firma_C = Sign_skC(id_v‖pk_v‖"cliente") }
    M->>S: REGISTRO { id_v, pk_m, firma_C }   %% Caso 1: altera pk_v
    note right of S: Verifica firma_C con trusted cliente:<br/>mensaje recalculado sobre pk_m ≠ pk_v
    S-->>M: ABORTADO (firma inválida)  ⟵ RECHAZO (no se envía s_v)
    M-->>C: ABORTADO
    end

    rect rgb(255,240,240)
    note over C,S: Caso 2 — el proxy adjunta su propia clave de verificación
    C->>M: REGISTRO { id_v, pk_v, firma_C }
    M->>S: REGISTRO { id_v, pk_m, firma_M, pk_firma_cliente = pk_atacante }
    note right of S: pk_firma_cliente ≠ trusted_keys/cliente
    S-->>M: ABORTADO (clave de firma no confiable)  ⟵ RECHAZO
    M-->>C: ABORTADO
    end

    rect rgb(235,255,235)
    note over C,S: Flujo legítimo (sin proxy)
    C->>S: REGISTRO { id_v, pk_v, firma_C }
    S-->>C: REGISTRO_OK { pk_s }
    C->>S: SOLICITAR_SEMILLA { id_v }
    note over S: s_v ← generar_semilla_maestra(); autorizado=False
    S-->>C: SEMILLA { OAEP(pk_v, s_v), firma_S = Sign_skS(id_v‖C_S‖"servidor") }
    note over C: Verifica firma_S con trusted servidor ANTES de usar s_v
    C->>S: ACK { id_v }
    note over C: Paso 3: K_i=HMAC(s_v,i); AES-GCM(K_i, AAD=id_v‖i); borra s_v,K_i
    end

    rect rgb(245,240,255)
    note over C,S: Paso 4/5a/6 — reinicio y recuperación autorizada
    C->>S: RECUPERAR { id_v, evento_autorizacion=True, firma_C }
    note over S: autorizado=True; cifra con pk_v del Paso 1 y firma C_S
    S-->>C: SEMILLA_RECUPERADA { OAEP(pk_v, s_v), firma_S }
    note over C: Verifica firma_S; regenera K_i; verifica tag/AAD; compara byte a byte
    end
```

**Punto exacto de rechazo.** La defensa corta en el **Paso 1 (REGISTRO)**, en el
servidor, **antes de generar o enviar `s_v`**:
- *Caso 1:* `Verify(trusted_cliente, firma_C, id_v‖pk_m‖"cliente")` falla porque
  el cliente firmó sobre `pk_v`, no sobre `pk_m`.
- *Caso 2:* la clave de verificación adjunta `pk_firma_cliente` no coincide con la
  pre-compartida en `trusted_keys/`, luego se rechaza aunque la firma sea
  internamente consistente con la clave del atacante.

Simétricamente, en el **Paso 2** el cliente verifica `firma_S` sobre el
criptograma; si el proxy re-cifrara `s_v`, la firma del servidor dejaría de
validar y el cliente abortaría sin usar la semilla.

### 4.2. Diagrama ASCII (resumen compacto)

```
 Cliente (Bob)              Proxy (M)                 Servidor (Alice)
      |  REGISTRO(id_v, pk_v, firma_C)  |                     |
      |-------------------------------->|  pk_v -> pk_m       |
      |                                 |-------------------->|  Verify(trusted_C,
      |                                 |                     |   firma_C sobre pk_m) = FALLA
      |            ABORTADO             |      ABORTADO       |----X  NO genera s_v
      |<--------------------------------|<--------------------|      (RECHAZO aquí)
```

---

## 5. Análisis matemático del generador de semillas

### 5.1. El generador

```python
configuracion = secrets.randbelow(9) + 16   # c uniforme en {16,...,24}
valor        = secrets.randbelow(1 << configuracion)   # uniforme en [0, 2^c)
return valor.to_bytes(32, "big")
```

Sea `c = configuracion`. Entonces `c` es **uniforme** sobre los 9 valores
`{16,…,24}`, cada uno con probabilidad `1/9`. Dado `c`, `valor` es uniforme en
`[0, 2^c)`. Como `c ≤ 24`, siempre se cumple `valor < 2²⁴`: el espacio efectivo
es `[0, 2²⁴)` — unos **16.7 millones** de valores, frente a los `2²⁵⁶` que
sugeriría una semilla de 32 bytes.

### 5.2. La distribución **no** es uniforme en `[0, 2²⁴)`

`valor` es una **mezcla** de 9 uniformes de distinta amplitud. Su función de masa es

$$
\Pr[\text{valor}=v]=\frac{1}{9}\sum_{c=16}^{24}\frac{[\,v<2^{c}\,]}{2^{c}} .
$$

Los valores pequeños son alcanzables bajo **más** escalas `c`, de modo que son
**más probables**. En particular,

$$
\Pr[\text{valor}<2^{16}]=\frac{1}{9}\sum_{c=16}^{24}2^{16-c}
=\frac{1}{9}\left(2-2^{-8}\right)\approx 0{.}2218 .
$$

Es decir, **~22.2 %** de las semillas caen en el `0.4 %` inferior del rango
`[0,2²⁴)`. La interpretación "cada escala `2¹⁶…2²⁴` tiene probabilidad `1/9`"
es correcta a nivel de `c`: con probabilidad `1/9` la semilla queda acotada por
`2¹⁶`, con `1/9` por `2¹⁷`, etc. La mezcla resultante está **sesgada hacia
valores pequeños**.

### 5.3. Número esperado de intentos `E[N]`

La búsqueda recorre `0,1,2,…` hasta encontrar `valor`, por lo que
`N = valor + 1`. Usando `E[2^c] = \frac{1}{9}\sum_{c=16}^{24}2^{c}` y
`E[\text{valor}\mid c] = (2^{c}-1)/2`:

$$
\mathbb{E}[2^{c}]=\frac{2^{25}-2^{16}}{9}=\frac{33\,488\,896}{9}\approx 3\,720\,988{.}44,
$$
$$
\mathbb{E}[\text{valor}]=\frac{\mathbb{E}[2^{c}]-1}{2}\approx 1\,860\,493{.}72,
\qquad
\boxed{\;\mathbb{E}[N]\approx 1\,860\,495\;}
$$

**Comparación con lo uniforme.** Si `valor` fuese uniforme en `[0,2²⁴)`, sería
`E[N] = (2²⁴-1)/2 + 1 ≈ 8 388 609`. El sesgo hacia valores pequeños hace que el
atacante espere **~4.5× menos** intentos que en el caso uniforme: la no
uniformidad **favorece** al atacante en promedio.

### 5.4. Teórico vs. medido

| Magnitud | Teórico | Medido (prueba) |
|---|---|---|
| Valor de `s_v` | (aleatorio) | `150 071` (18 bits) |
| Intentos `N` | `E[N] ≈ 1 860 495` | `150 072` |
| Velocidad | — | `≈ 1.06 × 10⁵ cand/seg` |
| Tiempo | `E[N]/vel ≈ 17.6 s` | `1.42 s` |
| Peor caso `2²⁴` | `≈ 158 s` | — |

La corrida concreta fue una semilla con `c` pequeño (muy por debajo de la media),
lo que explica que `150 072 ≪ E[N]`. El tiempo esperado (~18 s) y el peor caso
(~2.6 min) confirman que el espacio es **trivialmente recorrible**.

> Los valores medidos dependen de la semilla aleatoria de cada corrida (p. ej.,
> otra ejecución registró `13 619` candidatos en `0.10 s`). Las cifras de esta
> tabla corresponden a la corrida guardada en `evidencias/02_investigacion_5b.log`;
> actualícelas con su propia ejecución. Lo invariante es que **todas** caen muy por
> debajo del peor caso `2²⁴` y por debajo o alrededor de `E[N]`.

### 5.5. Costo de recuperar `s_v` frente a descifrar `M` archivos

- **Recuperar `s_v`:** `E[N] ≈ 1.86 × 10⁶` iteraciones (peor caso `2²⁴ ≈ 1.68 × 10⁷`),
  cada una con **1 HMAC-SHA256 + 1 intento AES-GCM** (el tag actúa de oráculo).
- **Descifrar los `M` archivos** una vez conocida `s_v`: `M` operaciones
  (1 HMAC + 1 AES-GCM por archivo).

El cociente es

$$
\frac{\text{costo recuperación}}{\text{costo descifrado}}\approx\frac{\mathbb{E}[N]}{M}
\;\;\Rightarrow\;\; \frac{1\,860\,495}{3}\approx 6.2\times 10^{5}.
$$

El trabajo está **dominado por romper la semilla**; el número de archivos `M` es
irrelevante para la parte difícil. En términos prácticos: *se paga una vez*
(≈`2²¹` intentos esperados) para quebrar `s_v`, y luego descifrar cualquier
cantidad de archivos es esencialmente gratis y **lineal en `M`**. La robustez de
RSA-OAEP (≈`2¹¹²` de seguridad) y de AES-256 (`2²⁵⁶`) queda anulada por el
eslabón débil: la **entropía del generador**.

---

## 6. Decisiones de diseño de las firmas digitales

### 6.1. Esquema elegido: **Ed25519** (frente a RSA-PSS)

Se eligió **Ed25519** porque:
- Es **determinista** (no depende de un RNG en la firma, evitando fallos por
  aleatoriedad pobre), rápido y con firmas compactas de **64 bytes**.
- Ofrece ~**128 bits** de seguridad con claves pequeñas (32 B), sin los riesgos
  de relleno/parámetros de RSA.
- La API de `cryptography` es mínima y difícil de usar mal.

RSA-PSS(SHA-256) sería una alternativa válida (y se menciona en el enunciado);
Ed25519 se prefiere por simplicidad y robustez frente a errores de implementación.

### 6.2. Datos firmados vinculados a `id_v`

Se firma el trío determinista

```
mensaje = id_v || '|' || pk_cifrado || '|' || rol
```

- **`id_v`** liga la firma a una víctima concreta: una firma válida para un
  cliente no puede reutilizarse para otro (anti-*cross-identity*).
- **`pk_cifrado`** es el material que viaja en claro en ese paso (la `pk_v` en el
  REGISTRO; el criptograma `C_S` de `s_v` en el Paso 2). Firmar exactamente lo
  que va por el cable impide que el proxy altere `pk_v` o re-cifre `s_v` sin
  invalidar la firma.
- **`rol`** (`cliente`/`servidor`) da **separación de dominios**: evita que una
  firma de un rol se acepte como la del otro (anti-reflexión).

Es la misma idea que ya se usa en el AEAD (AAD = `id_v || i`): **atar el dato a su
contexto**.

### 6.3. Origen de la confianza previa (`trusted_keys/`)

Las claves **públicas de verificación** se distribuyen **fuera de banda** y se
guardan en `trusted_keys/`; **no viajan por la red**. Son el **ancla de
confianza**: las firmas solo *trasladan* confianza desde ese ancla, no la crean
de la nada. Sin un ancla pre-compartida, un intermediario podría inyectar su
propia clave de verificación (exactamente el **Caso 2**), y cualquier firma
"válida bajo su propia clave" sería aceptada. Por eso el servidor valida
**exclusivamente** contra `trusted_keys/` y rechaza toda clave adjunta que no
coincida. Es, en miniatura, el problema de la raíz de confianza de una PKI.

### 6.4. Por qué RSA-OAEP **por sí solo** no evita la sustitución de claves

RSA-OAEP aporta **confidencialidad** hacia *quien posea la clave pública usada*,
pero **no dice de quién es esa clave**. Cifrar `s_v` "hacia `pk_v`" no significa
nada si el atacante logró que el servidor crea que `pk_m` (la suya) es `pk_v`:
el servidor cifrará `s_v` para el atacante, con total corrección criptográfica.
En el lenguaje del Colab (§1.1): *"si un atacante sustituye la clave pública por
la suya, recibirá información cifrada para él; una conexión TCP por sí sola no
proporciona esa autenticidad"*. **Cifrado ≠ autenticación.** Hace falta
**autenticar el origen** de la clave pública — justo lo que aportan las firmas
ancladas en `trusted_keys/`.

---

## 7. Resultados de las pruebas (evidencias)

Generadas con `bash ejecutar_pruebas.sh` (carpeta `evidencias/`).

| Prueba | Evidencia | Resultado |
|---|---|---|
| 1. Cifrado + reinicio + recuperación | `01_cifrado_reinicio_recuperacion.log` | 3/3 archivos **idénticos** (bytes y SHA-256) |
| 2. Auditoría 5b (servidor apagado) | `02_investigacion_5b.log` | semilla hallada; `≈1.06×10⁵` cand/seg |
| 3. Proxy MITM sin defensa | `03_mitm_sin_defensa.log` | `s_v` **interceptada**; botín descifrado |
| 4a. Defensa — ciclo legítimo | `04_defensa_firmas.log` | cifrado + recuperación OK, 3/3 idénticos |
| 4b. Defensa — Caso 1 | `04_defensa_firmas.log` | **ABORTADO** (firma de cliente inválida) |
| 4c. Defensa — Caso 2 | `04_defensa_firmas.log` | **ABORTADO** (clave de firma no confiable); **sin** semilla robada |

---

## 8. Entorno en contenedores

`Dockerfile` (base `python:3.11-slim` + `cryptography`) y `docker-compose.yml`
aíslan **servidor**, **proxy** y **cliente** en contenedores separados sobre una
**red interna** (`internal: true`), cada uno con su **propio volumen** de datos
(`datos_servidor`, `datos_cliente`, `datos_proxy`) y un volumen compartido
`cifrados_compartidos` para que el proxy vea los `.enc.json` del cliente. Host y
puertos se parametrizan por variables (`SRV_HOST`, `SRV_PORT`, `PROXY_PORT`) y por
argumentos CLI. (La configuración se validó con `docker compose config`.)

---

## 9. Nota de seguridad y alcance

Trabajo con fines **educativos**. El borrado de secretos en RAM es *best-effort*
(Python no garantiza *zeroization*); `trusted_keys/` asume un canal de
distribución fuera de banda; la aritmética y los tiempos son docentes. No usar en
producción tal cual. El objetivo cumplido es mostrar, de extremo a extremo, que
**la seguridad de un sistema híbrido correcto puede colapsar por la entropía del
generador, y que la autenticación (firmas + ancla de confianza) es
imprescindible para resistir un intermediario.**
