#!/usr/bin/env bash
# ===========================================================================
# ejecutar_pruebas.sh — Generador de evidencias (Actividad III, Modelo A)
#
# Ejecuta las 4 pruebas exigidas y guarda cada log en evidencias/:
#   1. Cifrado, reinicio y recuperación autorizada (flujo legítimo).
#   2. Investigación 5b: fuerza bruta de la semilla con el SERVIDOR APAGADO.
#   3. Proxy MITM SIN defensa: intercepta s_v y descifra el botín.
#   4. Defensa Ed25519: rechaza Caso 1, rechaza Caso 2 y completa el ciclo
#      legítimo (cifrado + recuperación) a través de firmas.
#
# Requisitos: python en PATH con la librería cryptography. En Windows se
# ejecuta con Git Bash; usa powershell.exe para liberar los puertos.
#
# Uso:   bash ejecutar_pruebas.sh
# ===========================================================================
set -u
cd "$(dirname "$0")"

PY=${PYTHON:-python}
SRV=50000
PROXY=60000
EVID="evidencias"
mkdir -p "$EVID"

# --- utilidades --------------------------------------------------------------
liberar_puertos() {
  # Mata cualquier proceso que escuche en los puertos del laboratorio.
  powershell.exe -NoProfile -Command "
    for (\$k=0; \$k -lt 8; \$k++) {
      \$p = Get-NetTCPConnection -State Listen -LocalPort $SRV,$PROXY -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
      if (-not \$p) { break }
      foreach (\$x in \$p) { try { Stop-Process -Id \$x -Force -ErrorAction Stop } catch {} }
      Start-Sleep -Milliseconds 300
    }" >/dev/null 2>&1 || true
}

limpiar_estado_base() {
  rm -f cliente_sk.pem cliente_pk.pem cliente_id.txt servidor_sk.pem servidor_pk.pem db_servidor.json
  rm -rf archivos_cifrados archivos_originales archivos_recuperados archivos_atacados proxy_botin
}

limpiar_estado_firmas() {
  rm -f defensa_firmas/cliente_sk.pem defensa_firmas/cliente_pk.pem defensa_firmas/cliente_id.txt \
        defensa_firmas/servidor_sk.pem defensa_firmas/servidor_pk.pem defensa_firmas/db_servidor_firmado.json
  rm -rf defensa_firmas/archivos_cifrados defensa_firmas/archivos_originales \
         defensa_firmas/archivos_recuperados proxy_botin
}

banner() { echo; echo "============================================================"; echo " $1"; echo "============================================================"; }

# =============================================================================
# PRUEBA 1 — Cifrado, reinicio y recuperación
# =============================================================================
prueba_1() {
  local LOG="$EVID/01_cifrado_reinicio_recuperacion.log"
  { banner "PRUEBA 1: Cifrado, reinicio y recuperación autorizada"
    liberar_puertos; limpiar_estado_base
    "$PY" -u servidor.py --puerto $SRV & SRV_PID=$!
    sleep 2
    echo "--- [Paso 1-3] Cliente: cifrado ---"
    "$PY" -u cliente.py --puerto $SRV
    echo; echo "--- [Reinicio] (el cliente olvidó s_v; la pide al servidor) ---"
    echo "--- [Paso 4-6] Cliente: recuperación y comparación byte a byte ---"
    "$PY" -u cliente.py --modo recuperacion_servidor --puerto $SRV
    kill $SRV_PID 2>/dev/null; liberar_puertos
  } 2>&1 | tee "$LOG"
}

# =============================================================================
# PRUEBA 2 — Investigación 5b (servidor APAGADO)
# =============================================================================
prueba_2() {
  local LOG="$EVID/02_investigacion_5b.log"
  { banner "PRUEBA 2: Auditoría de entropía 5b (servidor apagado)"
    liberar_puertos   # garantiza que NO hay servidor en marcha
    echo "--- Servidor confirmado APAGADO. Fuerza bruta sobre el archivo i=0 ---"
    "$PY" -u investigacion_5b.py
  } 2>&1 | tee "$LOG"
}

# =============================================================================
# PRUEBA 3 — Proxy MITM sin defensa
# =============================================================================
prueba_3() {
  local LOG="$EVID/03_mitm_sin_defensa.log"
  { banner "PRUEBA 3: Proxy MITM SIN defensa (roba s_v)"
    liberar_puertos; limpiar_estado_base
    "$PY" -u servidor.py --puerto $SRV & SRV_PID=$!
    sleep 2
    "$PY" -u proxy_mitm.py --escucha $PROXY --servidor-puerto $SRV & PRX_PID=$!
    sleep 2
    echo "--- Cliente apuntando al PROXY (cree que es el servidor) ---"
    "$PY" -u cliente.py --puerto $PROXY
    echo; echo "--- El proxy descifra el BOTÍN con la s_v interceptada ---"
    "$PY" -u proxy_mitm.py --descifrar
    echo; echo "--- Semilla robada registrada por el proxy: ---"
    cat proxy_botin/semillas_robadas.json 2>/dev/null || echo "(no encontrada)"
    kill $SRV_PID $PRX_PID 2>/dev/null; liberar_puertos
  } 2>&1 | tee "$LOG"
}

# =============================================================================
# PRUEBA 4 — Defensa Ed25519 (Caso 1, Caso 2, ciclo legítimo)
# =============================================================================
prueba_4() {
  local LOG="$EVID/04_defensa_firmas.log"
  { banner "PRUEBA 4: Defensa con firmas Ed25519"
    liberar_puertos; limpiar_estado_firmas
    echo "--- Generando claves de confianza pre-compartidas ---"
    "$PY" -u defensa_firmas/setup_claves.py

    echo; echo ">>> (4a) CICLO LEGÍTIMO directo: cifrado + recuperación <<<"
    "$PY" -u defensa_firmas/servidor_firmado.py --puerto $SRV & SRV_PID=$!
    sleep 2
    "$PY" -u defensa_firmas/cliente_firmado.py --puerto $SRV
    "$PY" -u defensa_firmas/cliente_firmado.py --modo recuperacion_servidor --puerto $SRV

    echo; echo ">>> (4b) CASO 1: proxy sustituye pk_v sin tocar la firma -> RECHAZO <<<"
    "$PY" -u proxy_mitm.py --escucha $PROXY --servidor-puerto $SRV & PRX_PID=$!
    sleep 2
    "$PY" -u defensa_firmas/cliente_firmado.py --puerto $PROXY
    kill $PRX_PID 2>/dev/null; liberar_puertos
    # reabrir servidor (el liberar_puertos también lo cerró)
    "$PY" -u defensa_firmas/servidor_firmado.py --puerto $SRV & SRV_PID=$!
    sleep 2

    echo; echo ">>> (4c) CASO 2: proxy forja firma propia y adjunta su clave -> RECHAZO <<<"
    "$PY" -u proxy_mitm.py --escucha $PROXY --servidor-puerto $SRV --modo-suplantacion-firma & PRX_PID=$!
    sleep 2
    "$PY" -u defensa_firmas/cliente_firmado.py --puerto $PROXY

    echo; echo "--- ¿El proxy logró robar la semilla? (debe ser NO) ---"
    cat proxy_botin/semillas_robadas.json 2>/dev/null || echo "(ninguna semilla robada: defensa efectiva)"
    kill $SRV_PID $PRX_PID 2>/dev/null; liberar_puertos
  } 2>&1 | tee "$LOG"
}

# =============================================================================
main() {
  banner "GENERADOR DE EVIDENCIAS — Actividad III (Modelo A)"
  echo "Los logs se guardan en: $EVID/"
  prueba_1
  prueba_2
  prueba_3
  prueba_4
  banner "FIN. Evidencias en $EVID/"
  ls -1 "$EVID"
}

main "$@"
