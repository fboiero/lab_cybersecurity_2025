#!/bin/bash
###############################################################################
# Script de Configuración - Clase 7
# Seguridad en la Nube y Virtualización
#
# Descripción: Configura el entorno de laboratorio automáticamente
# Autor: UTN - Laboratorio de Ciberseguridad
# Versión: 1.0
###############################################################################

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_header() {
    echo ""
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

check_command() {
    if command -v $1 &> /dev/null; then
        print_success "$1 está instalado"
        return 0
    else
        print_error "$1 NO está instalado"
        return 1
    fi
}

###############################################################################
# INICIO DEL SCRIPT
###############################################################################

print_header "CONFIGURACIÓN DEL ENTORNO - CLASE 7"

print_info "Este script configurará automáticamente el entorno de laboratorio"
print_info "Presiona Ctrl+C para cancelar en cualquier momento"
echo ""

# Verificar que estamos en el directorio correcto
if [ ! -d "scripts" ] || [ ! -d "docs" ]; then
    print_error "Error: Este script debe ejecutarse desde el directorio clase7"
    exit 1
fi

###############################################################################
# 1. VERIFICAR REQUISITOS DEL SISTEMA
###############################################################################

print_header "1. VERIFICANDO REQUISITOS DEL SISTEMA"

# Python
if check_command python3; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_info "Versión de Python: $PYTHON_VERSION"

    # Verificar que es >= 3.8
    REQUIRED_VERSION="3.8"
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
        print_success "Versión de Python es adecuada (>= 3.8)"
    else
        print_error "Python 3.8 o superior es requerido. Versión actual: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 no está instalado"
    print_info "Instala Python 3.8 o superior antes de continuar"
    exit 1
fi

# pip
check_command pip3 || print_warning "pip3 no encontrado, intentando con pip"

# Git
check_command git

# AWS CLI (opcional)
if check_command aws; then
    AWS_VERSION=$(aws --version 2>&1 | cut -d' ' -f1)
    print_info "$AWS_VERSION"
else
    print_warning "AWS CLI no está instalado (opcional para usar LocalStack)"
fi

# Docker (opcional para LocalStack)
if check_command docker; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,$//')
    print_info "Docker versión: $DOCKER_VERSION"
else
    print_warning "Docker no está instalado (opcional para LocalStack)"
fi

###############################################################################
# 2. CREAR ENTORNO VIRTUAL
###############################################################################

print_header "2. CONFIGURANDO ENTORNO VIRTUAL DE PYTHON"

if [ -d "venv" ]; then
    print_warning "Entorno virtual ya existe"
    read -p "¿Deseas recrearlo? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        print_info "Eliminando entorno virtual existente..."
        rm -rf venv
    else
        print_info "Usando entorno virtual existente"
    fi
fi

if [ ! -d "venv" ]; then
    print_info "Creando entorno virtual..."
    python3 -m venv venv
    print_success "Entorno virtual creado"
fi

# Activar entorno virtual
print_info "Activando entorno virtual..."
source venv/bin/activate

# Verificar activación
if [ -z "$VIRTUAL_ENV" ]; then
    print_error "No se pudo activar el entorno virtual"
    exit 1
fi

print_success "Entorno virtual activado: $VIRTUAL_ENV"

###############################################################################
# 3. INSTALAR DEPENDENCIAS
###############################################################################

print_header "3. INSTALANDO DEPENDENCIAS DE PYTHON"

print_info "Actualizando pip..."
python -m pip install --upgrade pip --quiet

if [ -f "scripts/requirements.txt" ]; then
    print_info "Instalando dependencias desde requirements.txt..."
    pip install -r scripts/requirements.txt --quiet
    print_success "Dependencias instaladas correctamente"
else
    print_error "No se encontró scripts/requirements.txt"
    exit 1
fi

# Verificar instalación de boto3
python -c "import boto3" 2>/dev/null
if [ $? -eq 0 ]; then
    BOTO3_VERSION=$(python -c "import boto3; print(boto3.__version__)")
    print_success "boto3 versión $BOTO3_VERSION instalado correctamente"
else
    print_error "Error al instalar boto3"
    exit 1
fi

###############################################################################
# 4. CONFIGURAR PERMISOS DE SCRIPTS
###############################################################################

print_header "4. CONFIGURANDO PERMISOS DE SCRIPTS"

print_info "Haciendo scripts ejecutables..."

for script in scripts/*.py; do
    if [ -f "$script" ]; then
        chmod +x "$script"
        print_success "$(basename $script) es ahora ejecutable"
    fi
done

###############################################################################
# 5. VERIFICAR CONFIGURACIÓN DE AWS
###############################################################################

print_header "5. VERIFICANDO CONFIGURACIÓN DE AWS"

if [ -f "$HOME/.aws/credentials" ]; then
    print_success "Archivo de credenciales AWS encontrado"

    # Intentar verificar credenciales
    if command -v aws &> /dev/null; then
        print_info "Verificando credenciales AWS..."
        if aws sts get-caller-identity &> /dev/null; then
            ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
            USER_ARN=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
            print_success "Credenciales AWS válidas"
            print_info "Account ID: $ACCOUNT_ID"
            print_info "User ARN: $USER_ARN"
        else
            print_warning "Credenciales configuradas pero no válidas"
            print_info "Ejecuta 'aws configure' para reconfigurar"
        fi
    fi
else
    print_warning "No se encontraron credenciales de AWS"
    print_info "Para usar AWS real, ejecuta: aws configure"
    print_info "Para usar LocalStack, no es necesario"
fi

###############################################################################
# 6. VERIFICAR/CONFIGURAR LOCALSTACK (OPCIONAL)
###############################################################################

print_header "6. CONFIGURACIÓN DE LOCALSTACK (OPCIONAL)"

if command -v docker &> /dev/null; then
    print_info "Docker está disponible"

    # Verificar si LocalStack está corriendo
    if docker ps | grep -q localstack; then
        print_success "LocalStack está corriendo"

        # Verificar salud de LocalStack
        if curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1; then
            print_success "LocalStack está respondiendo correctamente"
        else
            print_warning "LocalStack corriendo pero no responde"
        fi
    else
        print_info "LocalStack no está corriendo"

        if [ -f "docker-compose.yml" ]; then
            read -p "¿Deseas iniciar LocalStack ahora? (s/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Ss]$ ]]; then
                print_info "Iniciando LocalStack..."
                docker-compose up -d

                # Esperar a que inicie
                print_info "Esperando a que LocalStack inicie..."
                sleep 10

                if curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1; then
                    print_success "LocalStack iniciado correctamente"
                else
                    print_warning "LocalStack puede no estar listo aún"
                    print_info "Verifica con: docker-compose logs localstack"
                fi
            fi
        else
            print_info "No se encontró docker-compose.yml"
            print_info "Puedes crear uno siguiendo las instrucciones en docs/SETUP.md"
        fi
    fi
else
    print_warning "Docker no está instalado"
    print_info "Instala Docker para usar LocalStack"
fi

###############################################################################
# 7. CREAR DIRECTORIOS ADICIONALES
###############################################################################

print_header "7. CREANDO DIRECTORIOS ADICIONALES"

DIRS=("resultados" "logs" "backups")

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        print_success "Directorio '$dir' creado"
    else
        print_info "Directorio '$dir' ya existe"
    fi
done

# Crear .gitignore para resultados y logs
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << EOF
# Python
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so

# Entorno
.env
.venv
env/
ENV/

# Resultados del laboratorio
resultados/
logs/
backups/
*.json
!templates/*.json

# Credenciales (¡NUNCA COMMITEAR!)
*credentials*
*.pem
*.key

# Temporales
*.log
*.tmp
.DS_Store
EOF
    print_success ".gitignore creado"
fi

###############################################################################
# 8. PRUEBA RÁPIDA
###############################################################################

print_header "8. EJECUTANDO PRUEBA RÁPIDA"

print_info "Probando imports de Python..."

cat > test_imports.py << 'EOF'
#!/usr/bin/env python3
import sys

try:
    import boto3
    print("✓ boto3")
except ImportError:
    print("✗ boto3")
    sys.exit(1)

try:
    import json
    print("✓ json")
except ImportError:
    print("✗ json")

try:
    from datetime import datetime
    print("✓ datetime")
except ImportError:
    print("✗ datetime")

print("\nTodos los módulos necesarios están disponibles")
EOF

python test_imports.py
if [ $? -eq 0 ]; then
    print_success "Todos los módulos Python están disponibles"
else
    print_error "Algunos módulos Python faltan"
fi

rm test_imports.py

###############################################################################
# 9. RESUMEN Y SIGUIENTES PASOS
###############################################################################

print_header "9. RESUMEN DE CONFIGURACIÓN"

echo -e "${GREEN}✓ Entorno virtual de Python creado y activado${NC}"
echo -e "${GREEN}✓ Dependencias instaladas${NC}"
echo -e "${GREEN}✓ Scripts configurados con permisos de ejecución${NC}"
echo -e "${GREEN}✓ Directorios de trabajo creados${NC}"

echo ""
print_header "SIGUIENTES PASOS"

echo "1. Mantén el entorno virtual activado:"
echo "   ${BLUE}source venv/bin/activate${NC}"
echo ""

echo "2. Configura tus credenciales AWS (si no lo has hecho):"
echo "   ${BLUE}aws configure${NC}"
echo ""

echo "3. (Opcional) Si usas LocalStack, asegúrate de que esté corriendo:"
echo "   ${BLUE}docker-compose up -d${NC}"
echo ""

echo "4. Ejecuta los scripts de laboratorio:"
echo "   ${BLUE}python scripts/detect_public_buckets.py${NC}"
echo ""

echo "5. Lee la documentación:"
echo "   - ${BLUE}docs/SETUP.md${NC} - Guía de configuración detallada"
echo "   - ${BLUE}docs/EJERCICIOS.md${NC} - Guía paso a paso de ejercicios"
echo "   - ${BLUE}docs/TROUBLESHOOTING.md${NC} - Solución de problemas"
echo ""

print_success "¡Configuración completada exitosamente!"

###############################################################################
# 10. GUARDAR INFORMACIÓN DEL ENTORNO
###############################################################################

print_info "Guardando información del entorno..."

cat > logs/setup_info.txt << EOF
Configuración del Entorno - Clase 7
Fecha: $(date)
Usuario: $USER
Sistema: $(uname -s) $(uname -r)

Python: $(python --version 2>&1)
pip: $(pip --version 2>&1)
boto3: $(python -c "import boto3; print(boto3.__version__)" 2>&1)

AWS CLI: $(aws --version 2>&1 || echo "No instalado")
Docker: $(docker --version 2>&1 || echo "No instalado")

Entorno virtual: $VIRTUAL_ENV
EOF

print_success "Información guardada en logs/setup_info.txt"

echo ""
print_info "Para desactivar el entorno virtual cuando termines:"
echo "   ${BLUE}deactivate${NC}"
echo ""

exit 0
