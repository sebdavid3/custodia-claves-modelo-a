#!/bin/sh
# Prepara el volumen de datos del contenedor y ejecuta el comando recibido.
set -e

: "${CRIPTO_DATA:=/app/datos}"
mkdir -p "$CRIPTO_DATA/archivos_trabajo"

# Si el cliente no tiene archivos de entrada, sembramos los de ejemplo.
if [ -z "$(ls -A "$CRIPTO_DATA/archivos_trabajo" 2>/dev/null)" ] && [ -d /app/_semillas_ejemplo ]; then
    cp -r /app/_semillas_ejemplo/. "$CRIPTO_DATA/archivos_trabajo/" 2>/dev/null || true
fi

exec "$@"
