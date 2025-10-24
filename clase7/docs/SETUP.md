# GUÍA DE CONFIGURACIÓN DEL ENTORNO
## Clase 7 - Seguridad en la Nube y Virtualización

---

## TABLA DE CONTENIDOS

1. [Requisitos Previos](#requisitos-previos)
2. [Configuración de AWS](#configuración-de-aws)
3. [Configuración de LocalStack (Alternativa)](#configuración-de-localstack)
4. [Instalación de Herramientas Python](#instalación-de-herramientas-python)
5. [Configuración de Entornos Virtualizados](#configuración-de-entornos-virtualizados)
6. [Verificación del Entorno](#verificación-del-entorno)
7. [Troubleshooting](#troubleshooting)

---

## REQUISITOS PREVIOS

### Hardware Mínimo
- CPU: 4 cores
- RAM: 8 GB (16 GB recomendado)
- Disco: 20 GB libres
- Virtualización habilitada en BIOS

### Software Base
- Sistema operativo: Linux, macOS, o Windows 10/11
- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Git
- Editor de texto (VSCode recomendado)

### Conocimientos Previos
- CLI de Linux/Unix
- Python básico
- Conceptos básicos de redes
- Fundamentos de cloud computing

---

## CONFIGURACIÓN DE AWS

### Opción 1: AWS Free Tier (Recomendado)

#### Paso 1: Crear Cuenta AWS

1. Ir a [aws.amazon.com](https://aws.amazon.com)
2. Click en "Create an AWS Account"
3. Completar el formulario con:
   - Email
   - Contraseña
   - Nombre de cuenta
4. Ingresar información de contacto
5. Agregar método de pago (tarjeta de crédito/débito)
   - **Nota:** No se cobrará si se mantiene dentro del Free Tier
6. Verificar identidad (llamada telefónica o SMS)
7. Seleccionar plan "Basic Support - Free"

#### Paso 2: Crear Usuario IAM para Laboratorio

**¡IMPORTANTE!** Nunca usar la cuenta root para operaciones diarias.

1. Iniciar sesión en AWS Console
2. Ir a servicio **IAM**
3. Click en "Users" → "Add users"
4. Configurar usuario:
   ```
   Nombre: lab-security-user
   Access type: ✓ Programmatic access
                ✓ AWS Management Console access
   ```
5. Establecer contraseña:
   ```
   ✓ Custom password
   □ Require password reset
   ```
6. Asignar permisos:
   - Seleccionar "Attach existing policies directly"
   - Buscar y seleccionar:
     - `ReadOnlyAccess` (para auditoría)
     - `IAMReadOnlyAccess`
     - `SecurityAudit`

   **Nota:** Para ejercicios de remediación, se necesitarán permisos adicionales.

7. (Opcional) Agregar tags:
   ```
   Key: Environment | Value: Lab
   Key: Course      | Value: Ciberseguridad
   ```

8. Revisar y crear usuario
9. **¡IMPORTANTE!** Guardar credenciales:
   - Access Key ID
   - Secret Access Key
   - Console Login URL
   - Guardar el archivo CSV

#### Paso 3: Configurar AWS CLI

```bash
# Instalar AWS CLI
# Linux/macOS
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verificar instalación
aws --version

# Configurar credenciales
aws configure

# Ingresar cuando se solicite:
AWS Access Key ID: [TU_ACCESS_KEY]
AWS Secret Access Key: [TU_SECRET_KEY]
Default region name: us-east-1
Default output format: json
```

#### Paso 4: Verificar Configuración

```bash
# Verificar identidad
aws sts get-caller-identity

# Deberías ver algo como:
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/lab-security-user"
# }

# Listar buckets S3 (puede estar vacío)
aws s3 ls
```

#### Paso 5: Habilitar MFA (Recomendado)

1. En AWS Console, ir a IAM
2. Seleccionar tu usuario
3. Tab "Security credentials"
4. Section "Multi-factor authentication (MFA)"
5. Click "Assign MFA device"
6. Seleccionar "Virtual MFA device"
7. Usar aplicación de autenticación (Google Authenticator, Authy, etc.)
8. Escanear código QR
9. Ingresar dos códigos consecutivos
10. Confirmar

---

## CONFIGURACIÓN DE LOCALSTACK

LocalStack es una alternativa local que simula servicios AWS sin costo.

### Requisitos
- Docker instalado
- Docker Compose instalado

### Instalación con Docker

#### Paso 1: Instalar Docker

**Linux (Ubuntu/Debian):**
```bash
# Actualizar repositorios
sudo apt-get update

# Instalar dependencias
sudo apt-get install ca-certificates curl gnupg lsb-release

# Agregar GPG key de Docker
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Configurar repositorio
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Instalar Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Verificar
sudo docker --version
```

**macOS:**
```bash
# Descargar e instalar Docker Desktop desde
# https://www.docker.com/products/docker-desktop
```

#### Paso 2: Crear docker-compose.yml

Crear archivo `docker-compose.yml`:

```yaml
version: '3.8'

services:
  localstack:
    image: localstack/localstack:latest
    container_name: localstack-lab
    ports:
      - "4566:4566"            # LocalStack Gateway
      - "4510-4559:4510-4559"  # External services port range
    environment:
      - SERVICES=s3,ec2,iam,cloudwatch
      - DEBUG=1
      - DATA_DIR=/tmp/localstack/data
      - DOCKER_HOST=unix:///var/run/docker.sock
    volumes:
      - "${TMPDIR:-/tmp}/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

#### Paso 3: Iniciar LocalStack

```bash
# Iniciar contenedor
docker-compose up -d

# Verificar estado
docker-compose ps

# Ver logs
docker-compose logs -f localstack
```

#### Paso 4: Configurar AWS CLI para LocalStack

```bash
# Configurar perfil para LocalStack
aws configure --profile localstack

# Ingresar valores ficticios:
AWS Access Key ID: test
AWS Secret Access Key: test
Default region name: us-east-1
Default output format: json

# Verificar conexión
aws --endpoint-url=http://localhost:4566 --profile localstack s3 ls
```

#### Paso 5: Crear Recursos de Prueba

```bash
# Crear bucket de prueba
aws --endpoint-url=http://localhost:4566 s3 mb s3://test-bucket

# Crear bucket público (para demostración)
aws --endpoint-url=http://localhost:4566 s3 mb s3://public-test-bucket
aws --endpoint-url=http://localhost:4566 s3api put-bucket-acl --bucket public-test-bucket --acl public-read

# Listar buckets
aws --endpoint-url=http://localhost:4566 s3 ls
```

---

## INSTALACIÓN DE HERRAMIENTAS PYTHON

### Paso 1: Verificar Python

```bash
# Verificar versión de Python
python3 --version

# Debe ser 3.8 o superior
```

### Paso 2: Crear Entorno Virtual

```bash
# Navegar a directorio de clase7
cd clase7

# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate

# Verificar activación (deberías ver (venv) en el prompt)
```

### Paso 3: Instalar Dependencias

```bash
# Actualizar pip
pip install --upgrade pip

# Instalar dependencias del proyecto
pip install -r scripts/requirements.txt

# Verificar instalación
pip list
```

### Paso 4: Verificar boto3

```bash
# Crear script de prueba
cat > test_boto3.py << 'EOF'
import boto3
import sys

try:
    s3 = boto3.client('s3')
    print("[+] boto3 configurado correctamente")

    # Intentar listar buckets
    response = s3.list_buckets()
    print(f"[+] Conexión exitosa. Buckets encontrados: {len(response.get('Buckets', []))}")
    sys.exit(0)
except Exception as e:
    print(f"[!] Error: {str(e)}")
    sys.exit(1)
EOF

# Ejecutar prueba
python test_boto3.py

# Limpiar
rm test_boto3.py
```

---

## CONFIGURACIÓN DE ENTORNOS VIRTUALIZADOS

Para el Ejercicio 4, necesitarás configurar máquinas virtuales.

### Opción 1: VirtualBox (Recomendado para Principiantes)

#### Instalación

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install virtualbox virtualbox-ext-pack

# Verificar
VBoxManage --version
```

**macOS:**
```bash
# Descargar desde https://www.virtualbox.org/
# O usar Homebrew:
brew install --cask virtualbox
```

#### Crear Red Interna

1. Abrir VirtualBox
2. File → Preferences → Network
3. Click en "+" para agregar red NAT
4. Configurar:
   ```
   Nombre: LabNetwork
   IPv4 Prefix: 192.168.56.0/24
   ```

#### Crear VMs

**VM 1 - Ubuntu Server:**
1. Descargar ISO de Ubuntu Server 22.04 LTS
2. Crear nueva VM:
   - Nombre: Ubuntu-Lab
   - Tipo: Linux
   - Versión: Ubuntu (64-bit)
   - RAM: 2048 MB
   - Disco: 20 GB
3. Configurar Red:
   - Adaptador 1: NAT (para Internet)
   - Adaptador 2: Red interna (LabNetwork)
4. Instalar Ubuntu Server

**VM 2 - Kali Linux:**
1. Descargar imagen de Kali Linux (versión VirtualBox)
2. Importar appliance
3. Configurar Red:
   - Adaptador 1: NAT
   - Adaptador 2: Red interna (LabNetwork)

### Opción 2: Proxmox (Avanzado)

Si tienes un servidor físico o nested virtualization:

1. Instalar Proxmox VE
2. Crear bridge para red interna
3. Crear VMs con plantillas
4. Configurar firewall de Proxmox

---

## VERIFICACIÓN DEL ENTORNO

### Checklist de Verificación

```bash
# 1. Python y dependencias
python3 --version                    # ≥ 3.8
pip list | grep boto3                # boto3 instalado

# 2. AWS CLI
aws --version                        # AWS CLI instalado
aws sts get-caller-identity          # Credenciales configuradas

# 3. Scripts de laboratorio
ls scripts/*.py                      # Scripts presentes
python scripts/detect_public_buckets.py --help  # (si tiene flag --help)

# 4. Docker (si usas LocalStack)
docker --version                     # Docker instalado
docker-compose ps                    # LocalStack corriendo

# 5. VirtualBox (si aplica)
VBoxManage --version                 # VirtualBox instalado
VBoxManage list vms                  # VMs creadas
```

### Script de Verificación Automatizado

```bash
# Crear script de verificación
cat > verify_setup.sh << 'EOF'
#!/bin/bash

echo "=== VERIFICACIÓN DE ENTORNO - CLASE 7 ==="
echo ""

# Python
echo -n "[*] Python 3.8+: "
python3 --version 2>/dev/null && echo "✓" || echo "✗ FALTA"

# boto3
echo -n "[*] boto3: "
python3 -c "import boto3" 2>/dev/null && echo "✓" || echo "✗ FALTA"

# AWS CLI
echo -n "[*] AWS CLI: "
aws --version 2>/dev/null && echo "✓" || echo "✗ FALTA"

# Credenciales AWS
echo -n "[*] Credenciales AWS: "
aws sts get-caller-identity &>/dev/null && echo "✓" || echo "✗ NO CONFIGURADAS"

# Scripts
echo -n "[*] Scripts de laboratorio: "
ls scripts/*.py &>/dev/null && echo "✓" || echo "✗ FALTAN"

# Docker
echo -n "[*] Docker: "
docker --version 2>/dev/null && echo "✓" || echo "✗ FALTA (opcional)"

echo ""
echo "=== FIN DE VERIFICACIÓN ==="
EOF

chmod +x verify_setup.sh
./verify_setup.sh
```

---

## TROUBLESHOOTING

### Problema: "No credentials found"

**Solución:**
```bash
# Verificar que existe el archivo de credenciales
ls -la ~/.aws/

# Debería haber:
# ~/.aws/config
# ~/.aws/credentials

# Si no existe, ejecutar:
aws configure

# O crear manualmente:
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
EOF

cat > ~/.aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

### Problema: "Access Denied" al listar buckets

**Solución:**
- Verificar que el usuario IAM tiene los permisos necesarios
- Revisar políticas asociadas al usuario
- Verificar que no hay Service Control Policies (SCPs) bloqueando

### Problema: LocalStack no inicia

**Solución:**
```bash
# Verificar logs
docker-compose logs localstack

# Reiniciar contenedor
docker-compose down
docker-compose up -d

# Verificar puerto 4566 no esté en uso
sudo lsof -i :4566
```

### Problema: boto3 no encuentra región

**Solución:**
```python
# En el código, especificar región explícitamente:
s3 = boto3.client('s3', region_name='us-east-1')

# O configurar variable de entorno:
export AWS_DEFAULT_REGION=us-east-1
```

### Problema: VirtualBox no inicia VMs

**Solución:**
```bash
# Verificar virtualización habilitada
egrep -c '(vmx|svm)' /proc/cpuinfo
# Si devuelve 0, habilitar en BIOS

# Verificar módulos del kernel
lsmod | grep vbox

# Reinstalar módulos si es necesario
sudo /sbin/vboxconfig
```

---

## RECURSOS ADICIONALES

### Documentación Oficial
- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [LocalStack Documentation](https://docs.localstack.cloud/)
- [VirtualBox Manual](https://www.virtualbox.org/manual/)

### Tutoriales Recomendados
- [AWS Free Tier Guide](https://aws.amazon.com/free/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Docker Getting Started](https://docs.docker.com/get-started/)

---

## SIGUIENTE PASO

Una vez completada la configuración, proceder a:
- **[EJERCICIOS.md](EJERCICIOS.md)** - Guía paso a paso de los ejercicios

---

**Actualizado:** Octubre 2025
**Autor:** UTN - Laboratorio de Ciberseguridad
