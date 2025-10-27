# LABORATORIO PRÁCTICO: SEGURIDAD EN DOCKER

## Universidad Tecnológica Nacional - FRVM
## Facultad Regional Villa María
## Laboratorio de Blockchain y Ciberseguridad

---

## ÍNDICE

1. [Introducción](#introducción)
2. [Objetivos del Laboratorio](#objetivos-del-laboratorio)
3. [Requisitos Previos](#requisitos-previos)
4. [Conceptos Teóricos](#conceptos-teóricos)
5. [Estructura del Laboratorio](#estructura-del-laboratorio)
6. [Ejercicios Prácticos](#ejercicios-prácticos)
7. [Casos de Estudio](#casos-de-estudio)
8. [Recursos Adicionales](#recursos-adicionales)

---

## INTRODUCCIÓN

Este laboratorio práctico está diseñado para enseñar conceptos de seguridad en contenedores Docker mediante ejercicios hands-on que los estudiantes pueden ejecutar localmente.

### ¿Por qué seguridad en Docker?

**Estadísticas alarmantes:**
- 80% de las organizaciones usan contenedores en producción
- 60% de las imágenes de Docker Hub contienen vulnerabilidades conocidas
- 40% de las empresas han sufrido incidentes de seguridad relacionados con contenedores

**Problemas comunes:**
- Imágenes con vulnerabilidades críticas
- Contenedores corriendo como root
- Secrets hardcodeados en imágenes
- Redes sin segmentación
- Volúmenes con permisos excesivos

---

## OBJETIVOS DEL LABORATORIO

Al finalizar este laboratorio, el estudiante será capaz de:

1. ✅ Identificar vulnerabilidades comunes en Dockerfiles e imágenes
2. ✅ Aplicar técnicas de hardening en contenedores
3. ✅ Escanear imágenes con herramientas automatizadas (Trivy, Grype)
4. ✅ Implementar el principio de mínimo privilegio en contenedores
5. ✅ Configurar redes seguras entre contenedores
6. ✅ Gestionar secrets de forma segura
7. ✅ Detectar y prevenir container escape
8. ✅ Aplicar Docker Bench Security Best Practices

---

## REQUISITOS PREVIOS

### Software Necesario

```bash
# Docker y Docker Compose
docker --version  # >= 24.0
docker-compose --version  # >= 2.20

# Python 3.8+
python3 --version

# Herramientas de escaneo
# Trivy (se instalará en el laboratorio)
# Docker Bench Security (se clonará)
```

### Conocimientos Previos

- Conceptos básicos de Docker (imágenes, contenedores, volúmenes)
- Comandos de Linux
- Fundamentos de redes
- Python básico

### Instalación de Herramientas

```bash
# Clonar el repositorio
cd clase7/lab_docker_security

# Ejecutar script de setup
chmod +x scripts/setup.sh
./scripts/setup.sh
```

---

## CONCEPTOS TEÓRICOS

### 1. ARQUITECTURA DE DOCKER Y SUPERFICIE DE ATAQUE

#### Componentes de Docker

```
┌─────────────────────────────────────────┐
│         Docker Client (CLI)             │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Docker Daemon (dockerd)         │
│  ┌───────────────────────────────────┐  │
│  │     containerd (runtime)          │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │   runc (OCI runtime)        │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        Linux Kernel                     │
│  (namespaces, cgroups, capabilities)    │
└─────────────────────────────────────────┘
```

#### Superficie de Ataque

**Vectores de ataque principales:**

1. **Imagen Vulnerable**
   - CVEs en dependencias
   - Malware embebido
   - Backdoors

2. **Configuración Insegura**
   - Contenedor como root
   - Capabilities excesivas
   - Volúmenes mal configurados

3. **Runtime Vulnerabilities**
   - Container escape
   - Kernel exploits
   - Breakout via Docker socket

4. **Supply Chain**
   - Imágenes de fuentes no confiables
   - Layer poisoning
   - Dependency confusion

---

### 2. DOCKER SECURITY FEATURES

#### Namespaces

Aislamiento de recursos del sistema:

- **PID namespace:** Procesos aislados
- **NET namespace:** Stack de red propio
- **MNT namespace:** Sistema de archivos aislado
- **UTS namespace:** Hostname independiente
- **IPC namespace:** Comunicación interprocesos aislada
- **USER namespace:** Mapeo de UIDs

```bash
# Ver namespaces de un contenedor
docker inspect <container_id> | grep -A 10 "Namespaces"

# Ejecutar proceso en namespace específico
nsenter --target <pid> --mount --uts --ipc --net --pid
```

#### Control Groups (cgroups)

Limitar recursos del contenedor:

```yaml
# docker-compose.yml
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M
```

#### Linux Capabilities

En lugar de root completo, otorgar capabilities específicas:

```bash
# Listar capabilities de un contenedor
docker run --rm alpine sh -c 'apk add -U libcap; capsh --print'

# Ejecutar sin capabilities
docker run --rm --cap-drop=ALL alpine

# Agregar solo las necesarias
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```

**Capabilities peligrosas:**
- `CAP_SYS_ADMIN` - Administración del sistema
- `CAP_NET_ADMIN` - Configuración de red
- `CAP_SYS_PTRACE` - Debugging de procesos
- `CAP_DAC_OVERRIDE` - Bypass de permisos de archivos

#### Seccomp Profiles

Filtros de syscalls:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "close"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# Aplicar perfil seccomp personalizado
docker run --security-opt seccomp=profile.json myimage
```

#### AppArmor / SELinux

Mandatory Access Control (MAC):

```bash
# Verificar perfil AppArmor
docker inspect <container> | grep AppArmorProfile

# Usar perfil personalizado
docker run --security-opt apparmor=docker-custom myimage
```

---

### 3. VULNERABILIDADES COMUNES

#### A. Contenedores como Root

**Problema:**
```dockerfile
# Dockerfile INSEGURO
FROM ubuntu:22.04
COPY app /app
CMD ["/app/server"]
```

Dentro del contenedor, el proceso corre como UID 0 (root).

**Impacto:**
- Si hay escape, el atacante tiene root en el host
- Puede modificar archivos en volúmenes montados
- Mayor superficie de ataque

**Solución:**
```dockerfile
# Dockerfile SEGURO
FROM ubuntu:22.04
RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --chown=appuser:appuser app /app
USER appuser
CMD ["/app/server"]
```

---

#### B. Secrets en Imágenes

**Problema:**
```dockerfile
# Dockerfile INSEGURO
FROM python:3.9
ENV DB_PASSWORD=supersecret123
COPY . /app
```

El secreto queda permanente en la layer de la imagen.

**Impacto:**
- Cualquiera con acceso a la imagen puede ver el secret
- Persiste incluso si se elimina en capas posteriores
- Puede filtrarse en registries públicos

**Solución 1: Build-time Secrets (BuildKit)**
```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.9
RUN --mount=type=secret,id=db_pass \
    export DB_PASSWORD=$(cat /run/secrets/db_pass) && \
    # usar el secreto aquí
```

```bash
docker buildx build --secret id=db_pass,src=./secrets/db_pass .
```

**Solución 2: Runtime Secrets (Docker Secrets)**
```yaml
# docker-compose.yml
services:
  app:
    image: myapp
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

---

#### C. Imágenes con Vulnerabilidades

**Problema:**
Usar imágenes base desactualizadas o con CVEs conocidos.

**Ejemplo:**
```dockerfile
FROM node:14  # Versión antigua con vulnerabilidades
```

**Solución:**
```dockerfile
# 1. Usar versiones específicas y actualizadas
FROM node:20-alpine3.19

# 2. Escanear imagen antes de usar
# $ trivy image node:20-alpine3.19

# 3. Imagen minimal (distroless)
FROM gcr.io/distroless/nodejs20-debian12
```

**Herramientas de escaneo:**
```bash
# Trivy
trivy image myapp:latest

# Grype
grype myapp:latest

# Docker Scout
docker scout cves myapp:latest
```

---

#### D. Volúmenes Inseguros

**Problema:**
```bash
# Montar Docker socket (MUY PELIGROSO)
docker run -v /var/run/docker.sock:/var/run/docker.sock myapp
```

**Impacto:**
Acceso completo al daemon de Docker = root en el host.

**Exploit:**
```bash
# Desde dentro del contenedor
docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
# Ahora tienes shell como root en el host
```

**Solución:**
- NO montar el Docker socket a menos que sea absolutamente necesario
- Si es necesario, usar Docker socket proxy con políticas estrictas
- Considerar alternativas como Docker API con autenticación

---

#### E. Redes Sin Segmentación

**Problema:**
Todos los contenedores en la red `bridge` por defecto pueden comunicarse.

```bash
docker run -d --name db mysql
docker run -d --name web nginx
docker run -d --name attacker alpine
```

El contenedor `attacker` puede alcanzar `db` directamente.

**Solución:**
```yaml
# docker-compose.yml
services:
  db:
    image: postgres
    networks:
      - backend

  api:
    image: myapi
    networks:
      - backend
      - frontend

  web:
    image: nginx
    networks:
      - frontend

networks:
  backend:
    internal: true  # Sin acceso a Internet
  frontend:
```

---

### 4. CONTAINER ESCAPE

#### ¿Qué es Container Escape?

Escapar del aislamiento del contenedor para obtener acceso al host.

#### Técnicas Comunes

**A. Privileged Container**

```bash
# Contenedor privilegiado
docker run --privileged -it alpine sh
```

Dentro del contenedor:
```bash
# Listar dispositivos del host
fdisk -l

# Montar disco del host
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Ahora puedes leer/escribir archivos del host
cat /mnt/host/etc/shadow
```

**B. Via Docker Socket**

Si el socket está montado:
```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker:latest sh
```

Crear contenedor privilegiado con acceso al host:
```bash
docker run -it --privileged --pid=host --net=host --ipc=host \
  -v /:/host ubuntu chroot /host bash
```

**C. Via Kernel Exploits**

Explotar vulnerabilidades en el kernel compartido:
```bash
# CVE-2022-0847 (Dirty Pipe)
# CVE-2021-22555 (Netfilter heap overflow)
# CVE-2016-5195 (Dirty COW)
```

**D. Via Capabilities**

Con `CAP_SYS_ADMIN`:
```bash
docker run --cap-add=SYS_ADMIN -it alpine sh

# Dentro del contenedor
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
# Exploit para ejecutar comandos en el host
```

---

### 5. HARDENING BEST PRACTICES

#### Checklist de Seguridad

**1. Imagen Base**
- ✅ Usar imágenes oficiales
- ✅ Versiones específicas (no `latest`)
- ✅ Imágenes minimal (alpine, distroless)
- ✅ Escanear con Trivy/Grype

**2. Dockerfile**
- ✅ Usuario no-root
- ✅ No guardar secrets
- ✅ Multi-stage builds
- ✅ Minimizar layers
- ✅ COPY en lugar de ADD
- ✅ Verificar checksums

**3. Runtime**
- ✅ Drop capabilities innecesarias
- ✅ Read-only filesystem
- ✅ No privileged
- ✅ Limites de recursos
- ✅ Seccomp/AppArmor profiles

**4. Redes**
- ✅ Redes personalizadas
- ✅ Segmentación por función
- ✅ Least privilege networking
- ✅ Firewall rules

**5. Secrets**
- ✅ Docker Secrets / Vault
- ✅ Variables de entorno desde archivos
- ✅ NO hardcodear en imagen
- ✅ Rotar regularmente

---

## ESTRUCTURA DEL LABORATORIO

```
lab_docker_security/
├── README.md                          (este archivo)
├── vulnerable_app/
│   ├── Dockerfile.vulnerable          (Dockerfile inseguro)
│   ├── Dockerfile.secure              (Dockerfile hardening)
│   ├── app.py                         (Aplicación de ejemplo)
│   ├── requirements.txt
│   └── docker-compose.vulnerable.yml
├── secure_app/
│   ├── Dockerfile                     (Dockerfile seguro)
│   ├── app.py
│   ├── docker-compose.yml
│   └── seccomp-profile.json
├── scripts/
│   ├── setup.sh                       (Instalar herramientas)
│   ├── scan_image.sh                  (Escanear con Trivy)
│   ├── run_docker_bench.sh            (Docker Bench Security)
│   └── exploit_examples.sh            (Demos de exploits)
├── docs/
│   ├── EJERCICIOS.md                  (Guía de ejercicios)
│   ├── SOLUCIONES.md                  (Soluciones paso a paso)
│   └── TROUBLESHOOTING.md
└── docker-compose-examples/
    ├── networks-segmentation.yml
    ├── secrets-management.yml
    └── resource-limits.yml
```

---

## EJERCICIOS PRÁCTICOS

### EJERCICIO 1: Análisis de Dockerfile Vulnerable

**Objetivo:** Identificar problemas de seguridad en un Dockerfile.

**Archivo:** `vulnerable_app/Dockerfile.vulnerable`

**Tareas:**
1. Revisar el Dockerfile
2. Identificar 10 problemas de seguridad
3. Documentar el impacto de cada uno
4. Proponer soluciones

**Ver:** [docs/EJERCICIOS.md](docs/EJERCICIOS.md#ejercicio-1)

---

### EJERCICIO 2: Escaneo de Vulnerabilidades con Trivy

**Objetivo:** Escanear imágenes y entender reportes de CVEs.

**Tareas:**
1. Escanear imagen vulnerable
2. Analizar el reporte
3. Priorizar vulnerabilidades por severidad
4. Remediar al menos 5 vulnerabilidades CRITICAL

**Comandos:**
```bash
# Construir imagen vulnerable
cd vulnerable_app
docker build -f Dockerfile.vulnerable -t vulnapp:v1 .

# Escanear
trivy image vulnapp:v1

# Exportar reporte JSON
trivy image -f json -o report.json vulnapp:v1
```

---

### EJERCICIO 3: Container Escape Simulation

**Objetivo:** Entender cómo funciona un container escape.

**Escenario:** Contenedor privilegiado con Docker socket montado.

**Tareas:**
1. Levantar contenedor vulnerable
2. Ejecutar exploit para acceder al host
3. Demostrar acceso a archivos del host
4. Documentar pasos de mitigación

**Ver:** [docs/EJERCICIOS.md](docs/EJERCICIOS.md#ejercicio-3)

---

### EJERCICIO 4: Implementar Multi-Stage Build Seguro

**Objetivo:** Reducir superficie de ataque con multi-stage builds.

**Tareas:**
1. Convertir Dockerfile monolítico a multi-stage
2. Usar imagen builder y imagen runtime separadas
3. Comparar tamaños de imágenes
4. Comparar número de vulnerabilidades

**Ejemplo:**
```dockerfile
# Stage 1: Build
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o app main.go

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

---

### EJERCICIO 5: Configuración de Redes Seguras

**Objetivo:** Implementar segmentación de red entre contenedores.

**Escenario:** Aplicación de 3 capas (web, api, db)

**Tareas:**
1. Crear redes separadas para frontend y backend
2. Configurar red interna para DB (sin Internet)
3. Verificar aislamiento con pruebas de conectividad
4. Documentar arquitectura de red

**Ver:** [docker-compose-examples/networks-segmentation.yml](docker-compose-examples/networks-segmentation.yml)

---

### EJERCICIO 6: Gestión Segura de Secrets

**Objetivo:** Implementar manejo de secretos sin hardcodear.

**Tareas:**
1. Identificar secrets hardcodeados en imagen vulnerable
2. Migrar a Docker Secrets
3. Verificar que secrets no quedan en layers
4. Implementar rotación de secrets

**Ver:** [docker-compose-examples/secrets-management.yml](docker-compose-examples/secrets-management.yml)

---

### EJERCICIO 7: Docker Bench Security

**Objetivo:** Auditar configuración de Docker con herramientas automatizadas.

**Tareas:**
1. Ejecutar Docker Bench Security
2. Analizar el reporte (WARN, INFO, PASS)
3. Remediar al menos 10 WARN
4. Documentar cambios realizados

**Comandos:**
```bash
# Ejecutar Docker Bench
./scripts/run_docker_bench.sh

# Revisar output
cat docker-bench-security.log
```

---

### EJERCICIO 8: Capabilities Mínimas

**Objetivo:** Aplicar principio de mínimo privilegio con capabilities.

**Tareas:**
1. Identificar capabilities necesarias para una aplicación
2. Ejecutar contenedor con `--cap-drop=ALL`
3. Agregar solo capabilities requeridas
4. Validar funcionalidad

**Ejemplo:**
```bash
# Servidor web necesita bindear puerto 80
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```

---

## CASOS DE ESTUDIO

### Caso 1: Tesla Kubernetes Cryptojacking (2018)

**Resumen:** Atacantes accedieron al panel de Kubernetes de Tesla sin autenticación y desplegaron miners de criptomonedas.

**Lecciones:**
- Siempre proteger APIs con autenticación
- Monitoreo de uso de CPU/memoria
- Network policies para limitar egress

**Simulación en el lab:**
Ver `docs/CASOS_PRACTICOS.md`

---

### Caso 2: Docker Hub Malicious Images (2020)

**Resumen:** Más de 20 imágenes en Docker Hub contenían malware y backdoors.

**Lecciones:**
- Verificar imágenes antes de usar
- Content trust con Docker Notary
- Usar registries privados para producción

---

## RECURSOS ADICIONALES

### Herramientas

- **Trivy:** https://github.com/aquasecurity/trivy
- **Docker Bench Security:** https://github.com/docker/docker-bench-security
- **Grype:** https://github.com/anchore/grype
- **Falco:** Runtime security monitoring
- **Clair:** Vulnerability scanner
- **Anchore:** Container analysis

### Documentación

- **CIS Docker Benchmark:** https://www.cisecurity.org/benchmark/docker
- **NIST SP 800-190:** Application Container Security Guide
- **OWASP Docker Security:** https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### Certificaciones

- **Docker Certified Associate (DCA)**
- **Kubernetes Security Specialist (CKS)**
- **GIAC Cloud Security Automation (GCSA)**

---

## ENTREGA DEL LABORATORIO

**Formato:** Reporte PDF + código fuente

**Contenido esperado:**

1. **Introducción**
   - Objetivos del laboratorio
   - Herramientas utilizadas

2. **Ejercicios Resueltos**
   - Capturas de pantalla
   - Comandos ejecutados
   - Explicación de resultados

3. **Análisis de Vulnerabilidades**
   - Tabla con CVEs encontrados
   - Severidad y impacto
   - Remediación aplicada

4. **Dockerfiles Mejorados**
   - Diff entre vulnerable y seguro
   - Justificación de cambios

5. **Conclusiones**
   - Lecciones aprendidas
   - Mejores prácticas aplicables a producción
   - Próximos pasos

**Rúbrica de evaluación:**
- Completitud de ejercicios: 40%
- Calidad del análisis: 30%
- Implementación de mejoras: 20%
- Documentación: 10%

---

## PRÓXIMOS PASOS

Después de completar este laboratorio, se recomienda:

1. **Laboratorio de Kubernetes Security**
   - Pod Security Policies
   - Network Policies
   - RBAC

2. **CI/CD Security**
   - Integrar escaneo en pipelines
   - Signed images
   - Admission controllers

3. **Runtime Security**
   - Falco para detección de anomalías
   - eBPF-based monitoring
   - Intrusion detection

---

## CONTACTO Y SOPORTE

**Instructor:** UTN FRVM - Laboratorio de Blockchain y Ciberseguridad

**Consultas:**
- Durante las clases prácticas
- Email: fboiero@frvm.utn.edu.ar
- GitHub Issues: [Repositorio del Lab](https://github.com/fboiero/lab_cybersecurity_2025)

---

## LICENCIA

© 2025 – Universidad Tecnológica Nacional - FRVM (Facultad Regional Villa María)
Laboratorio de Blockchain y Ciberseguridad

Material educativo de uso académico.

---

**Versión:** 1.0
**Última actualización:** Octubre 2025
**Autor:** UTN FRVM - Laboratorio de Ciberseguridad
