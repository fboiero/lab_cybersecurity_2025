#!/bin/bash
#
# Script para ejecutar Docker Bench Security
# UTN FRVM - Laboratorio de Ciberseguridad
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$SCRIPT_DIR/../docker-bench-security"
RESULTS_DIR="$SCRIPT_DIR/../results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "Docker Bench Security"
echo "UTN FRVM - Laboratorio de Ciberseguridad"
echo "=========================================="
echo

if [ ! -d "$BENCH_DIR" ]; then
    echo "Error: Docker Bench Security no encontrado."
    echo "Ejecutar primero: ./setup.sh"
    exit 1
fi

cd "$BENCH_DIR"

echo "Ejecutando audit de seguridad Docker..."
echo "Esto puede tomar varios minutos..."
echo

sudo sh docker-bench-security.sh | tee "$RESULTS_DIR/docker-bench_${TIMESTAMP}.log"

echo
echo "=========================================="
echo "Audit completado"
echo "=========================================="
echo
echo "Reporte guardado en: $RESULTS_DIR/docker-bench_${TIMESTAMP}.log"
echo
echo "Revisar secciones marcadas como:"
echo "  [WARN] - Advertencias que deben corregirse"
echo "  [FAIL] - Fallas críticas de seguridad"
echo
echo "Para más información: https://github.com/docker/docker-bench-security"
