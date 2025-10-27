# GUÍA DE EJERCICIOS - LABORATORIO DOCKER SECURITY

## Universidad Tecnológica Nacional - FRVM
## Facultad Regional Villa María
## Laboratorio de Blockchain y Ciberseguridad

---

## ÍNDICE

1. [Ejercicio 1: Análisis de Dockerfile Vulnerable](#ejercicio-1-análisis-de-dockerfile-vulnerable)
2. [Ejercicio 2: Escaneo con Trivy](#ejercicio-2-escaneo-con-trivy)
3. [Ejercicio 3: Hardening de Dockerfile](#ejercicio-3-hardening-de-dockerfile)
4. [Ejercicio 4: Docker Compose Seguro](#ejercicio-4-docker-compose-seguro)
5. [Ejercicio 5: Secrets Management](#ejercicio-5-secrets-management)
6. [Ejercicio 6: Network Segmentation](#ejercicio-6-network-segmentation)
7. [Ejercicio 7: Container Escape Demo](#ejercicio-7-container-escape-demo)
8. [Ejercicio 8: Docker Bench Security](#ejercicio-8-docker-bench-security)

---

## EJERCICIO 1: Análisis de Dockerfile Vulnerable

### Objetivos
- Identificar vulnerabilidades en un Dockerfile
- Entender el impacto de cada vulnerabilidad
- Proponer soluciones

### Pasos

#### 1.1 Revisar Dockerfile Vulnerable

```bash
cd vulnerable_app
cat Dockerfile.vulnerable
```

#### 1.2 Identificar Vulnerabilidades

Completa la siguiente tabla identificando 10 vulnerabilidades:

| # | Vulnerabilidad | Línea | Severidad | Impacto |
|---|---------------|-------|-----------|---------|
| 1 | Imagen base antigua | 6 | CRÍTICA | CVEs conocidos |
| 2 | Correr como root | - | CRÍTICA | Privilegios excesivos |
| 3 | Secrets hardcodeados | 17-21 | CRÍTICA | Exposición de credenciales |
| 4 | Permisos 777 | 42 | ALTA | Cualquiera puede modificar |
| 5 | Sudo sin password | 45-46 | CRÍTICA | Escalación trivial |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |

#### 1.3 Construir Imagen Vulnerable

```bash
docker build -f Dockerfile.vulnerable -t vulnapp:v1 .
```

#### 1.4 Inspeccionar Imagen

```bash
# Ver layers
docker history vulnapp:v1

# Ver tamaño
docker images vulnapp:v1

# Ver variables de ambiente
docker inspect vulnapp:v1 | grep -A 20 "Env"
```

**Pregunta:** ¿Puedes ver los secrets en las variables de ambiente?

#### 1.5 Ejecutar y Explorar

```bash
# Ejecutar contenedor
docker run -d --name vuln-test vulnapp:v1

# Conectarse al contenedor
docker exec -it vuln-test bash

# Dentro del contenedor, verificar:
whoami                    # ¿Qué usuario?
id                        # ¿Qué permisos?
ls -la /app               # ¿Qué permisos en archivos?
sudo whoami               # ¿Funciona sudo sin password?
cat /app/credentials.txt  # ¿Hay credenciales expuestas?
```

#### 1.6 Documentar Hallazgos

Crea un reporte con:
- Lista de vulnerabilidades encontradas
- Evidencias (capturas de pantalla)
- Solución propuesta para cada una

---

## EJERCICIO 2: Escaneo con Trivy

### Objetivos
- Usar Trivy para escanear vulnerabilidades
- Interpretar reportes de CVEs
- Priorizar remediación

### Pasos

#### 2.1 Escanear Imagen Vulnerable

```bash
cd ..
./scripts/scan_image.sh vulnapp:v1
```

#### 2.2 Analizar Reporte

```bash
# Ver reporte completo
cat results/vulnapp_v1_*.txt

# Ver solo críticas
trivy image --severity CRITICAL vulnapp:v1

# Buscar CVE específico
trivy image vulnapp:v1 | grep CVE-2023
```

#### 2.3 Completar Tabla de CVEs

| CVE ID | Paquete | Severidad | CVSS Score | Descripción | Fix Version |
|--------|---------|-----------|------------|-------------|-------------|
| | | | | | |
| | | | | | |
| | | | | | |

#### 2.4 Escanear Secrets

```bash
trivy image --scanners secret vulnapp:v1
```

**Pregunta:** ¿Qué secrets encontró Trivy?

#### 2.5 Comparar con Imagen Segura

```bash
cd secure_app
docker build -t secureapp:v1 .
cd ..
./scripts/scan_image.sh secureapp:v1
```

Comparar resultados:

| Métrica | vulnapp:v1 | secureapp:v1 |
|---------|------------|--------------|
| CRITICAL | | |
| HIGH | | |
| Tamaño imagen | | |
| Secrets encontrados | | |

---

## EJERCICIO 3: Hardening de Dockerfile

### Objetivos
- Aplicar mejores prácticas de seguridad
- Crear Dockerfile seguro desde cero
- Medir mejoras

### Pasos

#### 3.1 Crear Dockerfile Mejorado

Partiendo de `Dockerfile.vulnerable`, crea `Dockerfile.hardened` aplicando:

```dockerfile
# 1. Imagen base actualizada y minimal
FROM python:3.11-slim-bookworm AS builder

# 2. Multi-stage build
# ... (builder stage)

FROM python:3.11-slim-bookworm

# 3. Usuario no-root
RUN groupadd -r -g 10001 appuser && \
    useradd -r -u 10001 -g appuser -m -s /sbin/nologin appuser

# 4. Copiar solo lo necesario
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local
COPY --chown=appuser:appuser app.py .

# 5. Permisos restrictivos
RUN chmod -R 550 /app

# 6. Sin secrets hardcodeados
# ENV DB_PASSWORD=...  ❌ NO HACER ESTO

# 7. Usuario no-root al ejecutar
USER appuser

# 8. Healthcheck
HEALTHCHECK CMD python -c "import requests; requests.get('http://localhost:5000')" || exit 1

CMD ["python", "app.py"]
```

#### 3.2 Construir y Comparar

```bash
docker build -f Dockerfile.hardened -t vulnapp:hardened .

# Comparar tamaños
docker images | grep vulnapp

# Comparar vulnerabilidades
./scripts/scan_image.sh vulnapp:hardened
```

#### 3.3 Verificar Mejoras

```bash
# Ejecutar versión hardened
docker run -d --name hardened-test vulnapp:hardened

# Intentar ejecutar como root
docker exec -it hardened-test whoami
# Debe mostrar: appuser (no root)

# Intentar sudo
docker exec -it hardened-test sudo whoami
# Debe fallar: sudo no disponible

# Verificar permisos
docker exec -it hardened-test ls -la /app
```

---

## EJERCICIO 4: Docker Compose Seguro

### Objetivos
- Configurar docker-compose con mejores prácticas
- Aplicar límites de recursos
- Implementar segmentación de red

### Pasos

#### 4.1 Revisar docker-compose.vulnerable.yml

```bash
cd vulnerable_app
cat docker-compose.vulnerable.yml
```

Identificar problemas:
- [ ] Privileged mode
- [ ] Docker socket montado
- [ ] Secrets en environment
- [ ] Sin límites de recursos
- [ ] network_mode: host

#### 4.2 Crear docker-compose Seguro

```yaml
version: '3.8'

services:
  web:
    build: .
    image: secureapp:latest

    # Seguridad
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

    # Recursos
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M

    # Secrets
    secrets:
      - db_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password

    # Redes
    networks:
      - frontend

secrets:
  db_password:
    file: ./secrets/db_password.txt

networks:
  frontend:
    driver: bridge
```

#### 4.3 Levantar y Verificar

```bash
docker-compose up -d

# Verificar recursos
docker stats

# Verificar capabilities
docker inspect <container> | grep -A 20 CapDrop

# Verificar red
docker network inspect secure_frontend
```

---

## EJERCICIO 5: Secrets Management

### Objetivos
- Implementar gestión segura de secrets
- Evitar hardcodear credenciales
- Usar Docker Secrets

### Pasos

#### 5.1 Identificar Secrets Hardcodeados

```bash
cd vulnerable_app

# Buscar secrets en Dockerfile
grep -i "password\|secret\|key" Dockerfile.vulnerable

# Buscar en imagen
docker history vulnapp:v1 | grep -i "password\|secret"
```

#### 5.2 Crear Secrets

```bash
cd ../secure_app

# Generar secrets seguros
openssl rand -base64 32 > secrets/db_password.txt
openssl rand -hex 20 > secrets/api_key.txt

# Proteger archivos
chmod 600 secrets/*
```

#### 5.3 Usar Secrets en Aplicación

```python
# app.py
import os

# ❌ INCORRECTO
DB_PASSWORD = "hardcoded_password"

# ✅ CORRECTO - Leer desde archivo
try:
    with open('/run/secrets/db_password', 'r') as f:
        DB_PASSWORD = f.read().strip()
except FileNotFoundError:
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'default')
```

#### 5.4 Verificar Secrets No Quedan en Imagen

```bash
docker build -t secureapp:secrets .

# Buscar secrets en layers
docker history secureapp:secrets

# Buscar en filesystem de la imagen
docker run --rm secureapp:secrets find / -name "*password*" -o -name "*secret*" 2>/dev/null
```

---

## EJERCICIO 6: Network Segmentation

### Objetivos
- Implementar redes segmentadas
- Aislar servicios por función
- Prevenir lateral movement

### Pasos

#### 6.1 Arquitectura

```
Internet
   │
   ▼
┌──────────┐
│   web    │  (frontend network)
└────┬─────┘
     │
     ▼
┌──────────┐
│   api    │  (frontend + backend)
└────┬─────┘
     │
     ▼
┌──────────┐
│    db    │  (backend network only - internal)
└──────────┘
```

#### 6.2 Implementar

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # Sin acceso a Internet

services:
  web:
    networks:
      - frontend

  api:
    networks:
      - frontend
      - backend

  db:
    networks:
      - backend  # Solo backend, sin frontend
```

#### 6.3 Verificar Aislamiento

```bash
docker-compose up -d

# Desde web, intentar llegar a db (debe fallar)
docker-compose exec web ping db
# Connection refused

# Desde api, llegar a db (debe funcionar)
docker-compose exec api ping db
# Success

# Desde db, intentar Internet (debe fallar)
docker-compose exec db ping 8.8.8.8
# Network unreachable
```

---

## EJERCICIO 7: Container Escape Demo

### Objetivos
- Entender cómo funciona un container escape
- Ver el impacto de privileged mode
- Aprender a prevenir

### Pasos

⚠️ **ADVERTENCIA:** Este ejercicio es SOLO con fines educativos. NO ejecutar en sistemas productivos.

#### 7.1 Contenedor Privilegiado

```bash
# Ejecutar contenedor privilegiado
docker run --privileged -it --pid=host ubuntu bash
```

Dentro del contenedor:

```bash
# Ver dispositivos del host
fdisk -l

# Montar disco del host
mkdir /mnt/host
mount /dev/sda1 /mnt/host  # Ajustar según tu sistema

# Leer archivos del host
ls -la /mnt/host
cat /mnt/host/etc/passwd

# DEMOSTRACIÓN: Ahora tienes acceso completo al host
```

#### 7.2 Via Docker Socket

```bash
# Contenedor con Docker socket montado
docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker:latest sh
```

Dentro:

```bash
# Crear contenedor privilegiado con acceso al host
docker run -it --privileged --pid=host --net=host -v /:/host ubuntu chroot /host bash

# Ahora estás en el host, no en el contenedor
hostname
cat /etc/hostname
```

#### 7.3 Prevención

```yaml
# ✅ CORRECTO
services:
  app:
    privileged: false  # Nunca privileged
    # NO montar Docker socket
    # volumes:
    #   - /var/run/docker.sock:/var/run/docker.sock  ❌

    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Solo lo necesario

    security_opt:
      - no-new-privileges:true
```

---

## EJERCICIO 8: Docker Bench Security

### Objetivos
- Auditar configuración de Docker
- Implementar CIS Docker Benchmark
- Remediar hallazgos

### Pasos

#### 8.1 Ejecutar Docker Bench

```bash
./scripts/run_docker_bench.sh
```

#### 8.2 Analizar Reporte

```bash
cat results/docker-bench_*.log
```

Buscar secciones:
- `[WARN]` - Advertencias
- `[FAIL]` - Fallas críticas
- `[PASS]` - Configuraciones correctas
- `[INFO]` - Información

#### 8.3 Remediar Hallazgos

Ejemplo de hallazgos comunes:

**[WARN] 2.1 - Restrict network traffic between containers**
```bash
# Crear redes personalizadas en lugar de default bridge
docker network create --driver bridge isolated_network
```

**[WARN] 2.8 - Enable user namespace support**
```bash
# Configurar en /etc/docker/daemon.json
{
  "userns-remap": "default"
}

sudo systemctl restart docker
```

**[WARN] 4.1 - Ensure a user for the container has been created**
```dockerfile
# En Dockerfile
USER appuser
```

#### 8.4 Re-ejecutar y Comparar

```bash
# Después de remediar
./scripts/run_docker_bench.sh

# Comparar resultados
diff results/docker-bench_antes.log results/docker-bench_despues.log
```

---

## ENTREGA

### Formato

Crear un reporte PDF con:

1. **Portada**
   - Nombre del estudiante
   - Fecha
   - Título: "Laboratorio Docker Security - UTN FRVM"

2. **Ejercicio 1: Análisis de Vulnerabilidades**
   - Tabla completa de vulnerabilidades
   - Capturas de pantalla
   - Explicación de cada vulnerabilidad

3. **Ejercicio 2: Escaneo con Trivy**
   - Reportes de escaneo
   - Tabla de CVEs
   - Comparación vulnerable vs seguro

4. **Ejercicio 3: Hardening**
   - Dockerfile mejorado
   - Diff entre vulnerable y hardened
   - Métricas de mejora

5. **Ejercicios 4-8**
   - Configuraciones implementadas
   - Evidencias de funcionamiento
   - Lecciones aprendidas

6. **Conclusiones**
   - Principales vulnerabilidades encontradas
   - Mejores prácticas aplicadas
   - Recomendaciones para producción

### Rúbrica

| Criterio | Puntos |
|----------|--------|
| Completitud de ejercicios | 40 |
| Calidad del análisis | 30 |
| Implementaciones correctas | 20 |
| Documentación | 10 |
| **Total** | **100** |

---

© 2025 – Universidad Tecnológica Nacional - FRVM (Facultad Regional Villa María)
Laboratorio de Blockchain y Ciberseguridad
