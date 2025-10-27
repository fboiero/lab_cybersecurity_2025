#!/bin/bash
#
# Script para escanear imágenes Docker con Trivy
# UTN FRVM - Laboratorio de Ciberseguridad
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Verificar argumento
if [ $# -eq 0 ]; then
    echo "Uso: $0 <nombre-imagen>"
    echo "Ejemplo: $0 vulnapp:v1"
    exit 1
fi

IMAGE=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "Escaneando imagen: $IMAGE"
echo "=========================================="
echo

# Escaneo básico
echo -e "${BLUE}[1/5]${NC} Escaneo rápido de vulnerabilidades..."
trivy image --severity HIGH,CRITICAL "$IMAGE"

echo
echo -e "${BLUE}[2/5]${NC} Generando reporte detallado JSON..."
trivy image -f json -o "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json" "$IMAGE"
echo -e "${GREEN}✓ Reporte guardado en: $RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json${NC}"

echo
echo -e "${BLUE}[3/5]${NC} Generando reporte tabla..."
trivy image -f table -o "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.txt" "$IMAGE"
echo -e "${GREEN}✓ Reporte guardado en: $RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.txt${NC}"

echo
echo -e "${BLUE}[4/5]${NC} Escaneando secretos hardcodeados..."
trivy image --scanners secret "$IMAGE"

echo
echo -e "${BLUE}[5/5]${NC} Resumen de vulnerabilidades..."

# Parsear JSON y mostrar resumen
CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json")
HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json")
MEDIUM=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json")
LOW=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$RESULTS_DIR/${IMAGE//:/}_${TIMESTAMP}.json")

echo
echo "=========================================="
echo -e "${RED}CRITICAL: $CRITICAL${NC}"
echo -e "${YELLOW}HIGH:     $HIGH${NC}"
echo -e "${BLUE}MEDIUM:   $MEDIUM${NC}"
echo -e "LOW:      $LOW"
echo "=========================================="
echo

# Recomendaciones basadas en resultados
if [ "$CRITICAL" -gt 0 ]; then
    echo -e "${RED}⚠️  ATENCIÓN: Se encontraron $CRITICAL vulnerabilidades CRÍTICAS${NC}"
    echo "Esta imagen NO debe usarse en producción."
    echo
    echo "Recomendaciones:"
    echo "1. Actualizar imagen base"
    echo "2. Actualizar dependencias"
    echo "3. Revisar Dockerfile"
    echo "4. Ejecutar: trivy image --severity CRITICAL $IMAGE"
    exit 1
elif [ "$HIGH" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Se encontraron $HIGH vulnerabilidades HIGH${NC}"
    echo "Se recomienda remediar antes de usar en producción."
    exit 1
else
    echo -e "${GREEN}✓ No se encontraron vulnerabilidades críticas o altas${NC}"
    exit 0
fi
