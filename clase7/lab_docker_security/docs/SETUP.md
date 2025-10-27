# GUÍA DE SETUP - LABORATORIO DOCKER SECURITY

## Universidad Tecnológica Nacional - FRVM
## Facultad Regional Villa María

---

## Requisitos del Sistema

### Software Obligatorio

- **Docker:** >= 24.0
- **Docker Compose:** >= 2.20
- **Python:** >= 3.8
- **Git:** Última versión

### Software Opcional

- **Trivy:** Scanner de vulnerabilidades
- **jq:** Parser de JSON
- **curl/wget:** Para downloads

---

## Instalación Rápida

### Linux (Ubuntu/Debian)

```bash
# Actualizar sistema
sudo apt-get update && sudo apt-get upgrade -y

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Instalar Docker Compose
sudo apt-get install docker-compose-plugin

# Reiniciar sesión para aplicar cambios de grupo
```

### macOS

```bash
# Instalar Docker Desktop
# Descargar desde: https://www.docker.com/products/docker-desktop

# O con Homebrew
brew install --cask docker

# Iniciar Docker Desktop
open /Applications/Docker.app
```

### Windows

1. Descargar Docker Desktop: https://www.docker.com/products/docker-desktop
2. Instalar y reiniciar
3. Habilitar WSL2 si se solicita

---

## Setup del Laboratorio

### 1. Clonar Repositorio

```bash
git clone https://github.com/fboiero/lab_cybersecurity_2025.git
cd lab_cybersecurity_2025/clase7/lab_docker_security
```

### 2. Ejecutar Script de Setup

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

Este script:
- ✅ Verifica Docker y Docker Compose
- ✅ Instala Trivy
- ✅ Descarga Docker Bench Security
- ✅ Crea directorios necesarios
- ✅ Genera secrets de ejemplo
- ✅ Actualiza base de datos de vulnerabilidades

### 3. Verificar Instalación

```bash
# Docker
docker --version
docker-compose --version

# Trivy
trivy --version

# Permisos
docker ps
```

Si `docker ps` falla con error de permisos:

```bash
sudo usermod -aG docker $USER
# Cerrar sesión y volver a entrar
```

---

## Estructura del Laboratorio

```
lab_docker_security/
├── README.md                    # Teoría completa
├── vulnerable_app/              # App vulnerable
│   ├── Dockerfile.vulnerable
│   ├── Dockerfile.secure
│   ├── app.py
│   └── docker-compose.vulnerable.yml
├── secure_app/                  # App segura
│   ├── Dockerfile
│   ├── app.py
│   ├── docker-compose.yml
│   └── seccomp-profile.json
├── scripts/                     # Scripts de auditoría
│   ├── setup.sh
│   ├── scan_image.sh
│   └── run_docker_bench.sh
└── docs/                        # Documentación
    ├── EJERCICIOS.md            # Guía de ejercicios
    └── SETUP.md                 # Esta guía
```

---

## Primeros Pasos

### Ejercicio de Prueba

```bash
# 1. Construir imagen vulnerable
cd vulnerable_app
docker build -f Dockerfile.vulnerable -t vulnapp:test .

# 2. Escanear con Trivy
cd ..
./scripts/scan_image.sh vulnapp:test

# 3. Ver reporte
cat results/vulnapp_test_*.txt
```

Si ves vulnerabilidades CRITICAL y HIGH, ¡el lab está funcionando correctamente!

---

## Solución de Problemas

### Docker no inicia

**Linux:**
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

**macOS/Windows:**
- Abrir Docker Desktop manualmente
- Verificar que esté en "Running"

### Permisos denegados

```bash
# Agregar usuario a grupo docker
sudo usermod -aG docker $USER

# Aplicar cambios (requiere re-login)
newgrp docker
```

### Trivy no instala

```bash
# Instalación manual
wget https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz
tar zxvf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

### Error: "Cannot connect to Docker daemon"

```bash
# Verificar que Docker esté corriendo
docker info

# Si falla, iniciar daemon
sudo systemctl start docker  # Linux
# O abrir Docker Desktop (macOS/Windows)
```

---

## Recursos Adicionales

- [Documentación Docker](https://docs.docker.com/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Docker Bench Security](https://github.com/docker/docker-bench-security)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)

---

## Soporte

**Instructor:** UTN FRVM - Laboratorio de Ciberseguridad
**Email:** fboiero@frvm.utn.edu.ar
**GitHub:** https://github.com/fboiero/lab_cybersecurity_2025

---

© 2025 – Universidad Tecnológica Nacional - FRVM (Facultad Regional Villa María)
