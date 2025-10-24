# GUÍA DE TROUBLESHOOTING
## Clase 7 - Seguridad en la Nube y Virtualización

---

## ÍNDICE DE PROBLEMAS COMUNES

1. [Problemas de AWS y boto3](#problemas-de-aws-y-boto3)
2. [Problemas de LocalStack](#problemas-de-localstack)
3. [Problemas de Permisos](#problemas-de-permisos)
4. [Problemas de Red en VirtualBox](#problemas-de-red-en-virtualbox)
5. [Problemas de Python](#problemas-de-python)
6. [Errores de Scripts](#errores-de-scripts)

---

## PROBLEMAS DE AWS Y BOTO3

### Error: "NoCredentialsError: Unable to locate credentials"

**Síntoma:**
```
botocore.exceptions.NoCredentialsError: Unable to locate credentials
```

**Causas posibles:**
1. AWS CLI no configurado
2. Variables de entorno no establecidas
3. Archivo de credenciales no existe

**Soluciones:**

#### Solución 1: Configurar AWS CLI
```bash
aws configure
```
Ingresa tus credenciales cuando se solicite.

#### Solución 2: Verificar archivo de credenciales
```bash
cat ~/.aws/credentials

# Debería verse así:
# [default]
# aws_access_key_id = YOUR_KEY_ID
# aws_secret_access_key = YOUR_SECRET_KEY
```

Si no existe, créalo:
```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
EOF

chmod 600 ~/.aws/credentials
```

#### Solución 3: Variables de entorno
```bash
export AWS_ACCESS_KEY_ID="tu_access_key"
export AWS_SECRET_ACCESS_KEY="tu_secret_key"
export AWS_DEFAULT_REGION="us-east-1"
```

---

### Error: "AccessDenied" al ejecutar operaciones S3

**Síntoma:**
```
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the ListBuckets operation
```

**Causas:**
1. Usuario IAM sin permisos suficientes
2. Políticas restrictivas
3. Service Control Policies bloqueando

**Soluciones:**

#### Verificar permisos del usuario
```bash
# Ver usuario actual
aws sts get-caller-identity

# Listar políticas del usuario
aws iam list-user-policies --user-name TU_USUARIO

# Listar políticas administradas asociadas
aws iam list-attached-user-policies --user-name TU_USUARIO
```

#### Adjuntar política necesaria
```bash
# Para laboratorio, usar ReadOnlyAccess
aws iam attach-user-policy \
  --user-name TU_USUARIO \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

---

### Error: "InvalidAccessKeyId"

**Síntoma:**
```
The AWS Access Key Id you provided does not exist in our records.
```

**Soluciones:**

1. **Verificar que la clave no tiene espacios:**
```bash
# Ver credenciales (ocultar parte de la clave)
aws configure list
```

2. **Regenerar credenciales:**
```bash
# Crear nueva clave de acceso
aws iam create-access-key --user-name TU_USUARIO

# Actualizar configuración
aws configure
```

---

### Error: "SignatureDoesNotMatch"

**Síntoma:**
```
The request signature we calculated does not match the signature you provided.
```

**Causas:**
- Hora del sistema incorrecta
- Credenciales incorrectas

**Soluciones:**

```bash
# Verificar hora del sistema
date

# Sincronizar hora (Linux)
sudo ntpdate pool.ntp.org

# O usar systemd-timesyncd
sudo timedatectl set-ntp true
```

---

### Error: "RegionDisabledException"

**Síntoma:**
```
The region 'xx-xxxx-x' is disabled.
```

**Solución:**
```bash
# Usar región habilitada
aws configure set region us-east-1

# O en el código:
# boto3.client('s3', region_name='us-east-1')
```

---

## PROBLEMAS DE LOCALSTACK

### Error: LocalStack no inicia

**Síntoma:**
```bash
docker-compose up -d
# Contenedor se detiene inmediatamente
```

**Diagnóstico:**
```bash
# Ver logs
docker-compose logs localstack

# Ver estado
docker-compose ps
```

**Soluciones comunes:**

#### Puerto 4566 en uso
```bash
# Verificar qué está usando el puerto
sudo lsof -i :4566

# Matar proceso si es necesario
sudo kill -9 <PID>

# Reiniciar LocalStack
docker-compose down
docker-compose up -d
```

#### Problemas de permisos con Docker
```bash
# Agregar usuario al grupo docker
sudo usermod -aG docker $USER

# Cerrar sesión y volver a iniciar

# Verificar
docker ps
```

#### Docker Desktop no corriendo (macOS/Windows)
- Iniciar Docker Desktop
- Esperar a que aparezca el ícono verde
- Reintentar

---

### Error: "Could not connect to LocalStack"

**Síntoma:**
```
botocore.exceptions.EndpointConnectionError: Could not connect to the endpoint URL
```

**Soluciones:**

```bash
# Verificar que LocalStack está corriendo
docker ps | grep localstack

# Verificar puertos
netstat -tuln | grep 4566

# Probar conexión
curl http://localhost:4566/_localstack/health

# Debería devolver JSON con estado de servicios
```

**Usar endpoint correcto en scripts:**
```python
# Para LocalStack
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)
```

---

## PROBLEMAS DE PERMISOS

### Error: "Access denied when calling GetBucketAcl"

**Síntoma:**
```
An error occurred (AccessDenied) when calling the GetBucketAcl operation
```

**Causa:**
Usuario no tiene permiso `s3:GetBucketAcl`

**Solución:**

Agregar política con permisos necesarios:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetPublicAccessBlock",
      "s3:ListAllMyBuckets"
    ],
    "Resource": "*"
  }]
}
```

---

### Error: "You are not authorized to perform this operation"

**Causa:**
Falta de permisos específicos

**Diagnóstico:**
```bash
# Simular política (dry-run)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/USER \
  --action-names s3:ListBucket s3:GetBucketAcl

# Ver resultado de evaluación
```

---

## PROBLEMAS DE RED EN VIRTUALBOX

### VMs no se comunican entre sí

**Síntoma:**
```bash
ping 192.168.56.10
# No hay respuesta
```

**Verificaciones:**

#### 1. Configuración de red en VMs
```bash
# En cada VM, verificar interfaces
ip addr show

# Debería haber una interfaz en red 192.168.56.0/24
```

#### 2. Tipo de red correcto
```bash
# Verificar adaptadores
VBoxManage showvminfo "Ubuntu-Target" | grep NIC

# Debería verse:
# NIC 1: NAT
# NIC 2: Internal Network 'LabNetwork'
```

**Soluciones:**

#### Configurar interfaz manualmente
```bash
# En Ubuntu
sudo ip addr add 192.168.56.10/24 dev enp0s8
sudo ip link set enp0s8 up

# En Kali
sudo ip addr add 192.168.56.20/24 dev eth1
sudo ip link set eth1 up
```

#### Configuración persistente (Ubuntu)
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Agregar:
```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      addresses:
        - 192.168.56.10/24
```

Aplicar:
```bash
sudo netplan apply
```

---

### Firewall bloqueando conexiones

**Síntoma:**
ping funciona pero nmap no muestra puertos abiertos

**Verificar firewall:**
```bash
# Ubuntu
sudo ufw status

# Si está activo y bloqueando:
sudo ufw allow from 192.168.56.0/24
```

---

### Error: "VT-x is not available"

**Síntoma:**
```
VT-x/AMD-V hardware acceleration is not available on your system
```

**Causa:**
Virtualización no habilitada en BIOS

**Solución:**
1. Reiniciar computadora
2. Entrar a BIOS/UEFI (F2, Del, o F12 según fabricante)
3. Buscar opción:
   - Intel: "Intel VT-x" o "Virtualization Technology"
   - AMD: "AMD-V" o "SVM Mode"
4. Habilitar
5. Guardar y salir

---

## PROBLEMAS DE PYTHON

### Error: "ModuleNotFoundError: No module named 'boto3'"

**Síntoma:**
```python
ModuleNotFoundError: No module named 'boto3'
```

**Causas:**
1. boto3 no instalado
2. Entorno virtual no activado
3. Usando Python incorrecto

**Soluciones:**

#### Instalar boto3
```bash
pip install boto3

# O desde requirements.txt
pip install -r scripts/requirements.txt
```

#### Verificar entorno virtual
```bash
# Activar entorno virtual
source venv/bin/activate

# Verificar que está activo (debería aparecer (venv) en prompt)

# Verificar qué Python se está usando
which python
# Debería ser: /path/to/clase7/venv/bin/python

# Listar paquetes instalados
pip list
```

---

### Error: "Permission denied" al ejecutar script

**Síntoma:**
```bash
./detect_public_buckets.py
bash: ./detect_public_buckets.py: Permission denied
```

**Solución:**
```bash
# Dar permisos de ejecución
chmod +x scripts/detect_public_buckets.py

# O ejecutar con python explícitamente
python scripts/detect_public_buckets.py
```

---

### Error: Versión de Python incorrecta

**Síntoma:**
```
SyntaxError: invalid syntax
```

**Verificar versión:**
```bash
python --version
python3 --version

# Debe ser 3.8 o superior
```

**Solución:**
```bash
# Usar python3 explícitamente
python3 scripts/detect_public_buckets.py

# O crear alias
alias python=python3
```

---

## ERRORES DE SCRIPTS

### Error: "KeyError: 'Grants'" en detect_public_buckets.py

**Causa:**
Respuesta de API no tiene estructura esperada

**Solución:**

El script ya maneja esto con `.get()`:
```python
for grant in acl.get('Grants', []):
    # Esto no falla si 'Grants' no existe
```

Si persiste, verificar permisos:
```bash
aws s3api get-bucket-acl --bucket BUCKET_NAME
```

---

### Script se ejecuta pero no muestra resultados

**Diagnóstico:**

#### 1. Verificar que hay buckets
```bash
aws s3 ls
```

#### 2. Ejecutar con verbose
Modificar script para agregar más prints:
```python
print(f"[DEBUG] Analizando bucket: {bucket_name}")
```

#### 3. Verificar permisos de lectura
```bash
aws s3api get-bucket-acl --bucket BUCKET_NAME
```

---

### Error: "JSONDecodeError" al exportar resultados

**Causa:**
Problema al serializar objetos datetime

**Solución:**

El script ya incluye `default=str`:
```python
json.dump(results, f, indent=2, default=str)
```

---

## PROBLEMAS ESPECÍFICOS DE EJERCICIOS

### Ejercicio 1: No detecta bucket público

**Verificar que el bucket realmente es público:**
```bash
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Buscar en output:
# "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
```

**Verificar Block Public Access:**
```bash
aws s3api get-public-access-block --bucket BUCKET_NAME

# Si todos están en 'true', el bucket NO será accesible públicamente
# aunque tenga ACL pública
```

---

### Ejercicio 2: Política no aplica correctamente

**Verificar sintaxis JSON:**
```bash
# Validar JSON
cat templates/IAM_policy_example.json | jq .

# Si hay error de sintaxis, jq lo mostrará
```

**Verificar que la política está asociada:**
```bash
aws iam list-attached-user-policies --user-name USUARIO

# Debe aparecer en la lista
```

**Verificar que el ARN del recurso es correcto:**
```json
"Resource": "arn:aws:s3:::BUCKET_NAME/*"
              ^^^^^^^^^^^^^ verificar que coincide con tu bucket
```

---

### Ejercicio 3: Remediación no funciona

**Verificar orden de aplicación:**

1. Primero Block Public Access
2. Luego cambiar ACL
3. Luego aplicar bucket policy

**Esperar propagación:**
```bash
# Esperar 30 segundos después de cambios
sleep 30

# Luego verificar
curl https://BUCKET.s3.amazonaws.com/file.txt
```

---

### Ejercicio 4: Nmap no muestra puertos

**Verificar servicios corriendo en target:**
```bash
# En Ubuntu-Target
sudo systemctl status ssh
sudo systemctl status apache2
sudo systemctl status mysql

# Ver puertos en escucha
sudo netstat -tuln | grep LISTEN
```

**Verificar firewall:**
```bash
# Temporalmente deshabilitar para prueba
sudo ufw disable

# Probar nmap desde Kali

# Volver a habilitar
sudo ufw enable
```

---

## HERRAMIENTAS DE DIAGNÓSTICO

### Script de diagnóstico general

```bash
#!/bin/bash
echo "=== DIAGNÓSTICO GENERAL ==="

echo -n "Python: "
python3 --version

echo -n "AWS CLI: "
aws --version

echo -n "boto3: "
python3 -c "import boto3; print(boto3.__version__)" 2>/dev/null || echo "NO INSTALADO"

echo -n "Credenciales AWS: "
aws sts get-caller-identity &>/dev/null && echo "OK" || echo "NO CONFIGURADAS"

echo -n "Docker: "
docker --version 2>/dev/null || echo "NO INSTALADO"

echo -n "VirtualBox: "
VBoxManage --version 2>/dev/null || echo "NO INSTALADO"

echo "=== FIN DIAGNÓSTICO ==="
```

---

## RECURSOS ADICIONALES

### Logs útiles para debugging

```bash
# AWS CLI debug
aws s3 ls --debug

# Python verbose
python -v scripts/detect_public_buckets.py

# LocalStack logs
docker-compose logs -f localstack

# Sistema
journalctl -xe  # Linux
```

### Documentación oficial

- [AWS CLI Troubleshooting](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-troubleshooting.html)
- [boto3 Troubleshooting](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/error-handling.html)
- [LocalStack Docs](https://docs.localstack.cloud/getting-started/troubleshooting/)
- [VirtualBox Manual](https://www.virtualbox.org/manual/ch12.html)

---

## CONTACTO Y SOPORTE

Si el problema persiste:

1. **Revisar logs detallados**
2. **Buscar en issues de GitHub del curso**
3. **Consultar en foro de la materia**
4. **Contactar al instructor con:**
   - Descripción del problema
   - Mensaje de error completo
   - Pasos para reproducir
   - Salida de comandos de diagnóstico

---

**Actualizado:** Octubre 2025
**Autor:** UTN - Laboratorio de Ciberseguridad
