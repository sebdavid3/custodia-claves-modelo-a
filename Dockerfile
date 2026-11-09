# Imagen ligera común a servidor, cliente y proxy (Modelo A).
FROM python:3.11-slim

# Única dependencia del proyecto.
RUN pip install --no-cache-dir "cryptography>=42"

WORKDIR /app
COPY . /app

# Semillas de ejemplo para archivos_trabajo (el entrypoint las copia si el
# volumen de datos está vacío). Se conservan fuera de CRIPTO_DATA.
RUN cp -r /app/archivos_trabajo /app/_semillas_ejemplo || true

# Raíz de datos reubicable: cada contenedor monta aquí su propio volumen.
ENV CRIPTO_DATA=/app/datos

COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Por defecto arranca el servidor; compose sobreescribe el command por servicio.
CMD ["python", "servidor.py", "--host", "0.0.0.0", "--puerto", "50000"]
