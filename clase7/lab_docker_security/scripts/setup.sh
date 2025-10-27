#!/bin/bash
#
# Script de Setup para Laboratorio Docker Security
# UTN FRVM - Laboratorio de Ciberseguridad
#

set -e

echo "=========================================="
echo "Docker Security Lab - Setup"
echo "UTN FRVM - Laboratorio de Ciberseguridad"
echo "=========================================="
echo

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar Docker
echo -e "${YELLOW}[1/6]${NC} Verificando Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker no está instalado${NC}"
    echo "Instalar Docker desde: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker $(docker --version)${NC}"

# Verificar Docker Compose
echo -e "${YELLOW}[2/6]${NC} Verificando Docker Compose..."
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose no está instalado${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose disponible${NC}"

# Instalar Trivy
echo -e "${YELLOW}[3/6]${NC} Instalando Trivy..."
if ! command -v trivy &> /dev/null; then
    echo "Instalando Trivy..."

    # Detectar OS
    OS="$(uname -s)"
    case "${OS}" in
        Linux*)
            sudo apt-get install -y wget apt-transport-https gnupg lsb-release
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update
            sudo apt-get install -y trivy
            ;;
        Darwin*)
            if command -v brew &> /dev/null; then
                brew install trivy
            else
                echo -e "${RED}Homebrew no encontrado. Instalar manualmente desde: https://github.com/aquasecurity/trivy${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${YELLOW}OS no soportado automáticamente. Instalar Trivy manualmente.${NC}"
            ;;
    esac
else
    echo -e "${GREEN}✓ Trivy ya instalado: $(trivy --version | head -n1)${NC}"
fi

# Clonar Docker Bench Security
echo -e "${YELLOW}[4/6]${NC} Descargando Docker Bench Security..."
if [ ! -d "docker-bench-security" ]; then
    git clone https://github.com/docker/docker-bench-security.git
    echo -e "${GREEN}✓ Docker Bench Security clonado${NC}"
else
    echo -e "${GREEN}✓ Docker Bench Security ya existe${NC}"
    cd docker-bench-security && git pull && cd ..
fi

# Crear directorios necesarios
echo -e "${YELLOW}[5/6]${NC} Creando estructura de directorios..."
mkdir -p secure_app/secrets
mkdir -p secure_app/data/db
mkdir -p vulnerable_app/secrets
mkdir -p results

# Crear archivos de secrets de ejemplo
echo "db_secure_password_$(openssl rand -hex 16)" > secure_app/secrets/db_password.txt
echo "api_key_secure_$(openssl rand -hex 20)" > secure_app/secrets/api_key.txt

# Para vulnerable app
echo "admin123" > vulnerable_app/secrets/db_password.txt
echo "simple_api_key" > vulnerable_app/secrets/api_key.txt

chmod 600 secure_app/secrets/*
chmod 600 vulnerable_app/secrets/*

echo -e "${GREEN}✓ Secrets generados${NC}"

# Actualizar base de datos de Trivy
echo -e "${YELLOW}[6/6]${NC} Actualizando base de datos de vulnerabilidades..."
trivy image --download-db-only

echo
echo -e "${GREEN}=========================================="
echo "✓ Setup completado exitosamente"
echo "==========================================${NC}"
echo
echo "Próximos pasos:"
echo "1. cd vulnerable_app"
echo "2. docker build -f Dockerfile.vulnerable -t vulnapp:v1 ."
echo "3. ../scripts/scan_image.sh vulnapp:v1"
echo
echo "Para más información, ver: docs/EJERCICIOS.md"
