# Dockerfile SEGURO - Mejores prácticas aplicadas
# UTN FRVM - Laboratorio de Ciberseguridad

# syntax=docker/dockerfile:1

# Stage 1: Builder
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .

RUN pip install --user --no-cache-dir --upgrade pip && \
    pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim-bookworm

LABEL maintainer="UTN FRVM" \
      description="Aplicación web segura - Lab Docker Security"

RUN groupadd -r -g 10001 appuser && \
    useradd -r -u 10001 -g appuser -m -s /sbin/nologin appuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

WORKDIR /app
COPY --chown=appuser:appuser app.py .

RUN mkdir -p /app/files && \
    chown -R appuser:appuser /app && \
    chmod -R 550 /app && \
    chmod -R 770 /app/files

ENV PATH="/home/appuser/.local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000', timeout=2)" || exit 1

ENTRYPOINT ["python"]
CMD ["app.py"]
