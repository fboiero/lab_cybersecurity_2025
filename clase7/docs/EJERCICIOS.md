# GUÍA DETALLADA DE EJERCICIOS
## Clase 7 - Seguridad en la Nube y Virtualización

---

## TABLA DE CONTENIDOS

1. [Ejercicio 1: Escaneo de Configuraciones Inseguras](#ejercicio-1-escaneo-de-configuraciones-inseguras)
2. [Ejercicio 2: Política IAM Segura](#ejercicio-2-política-iam-segura)
3. [Ejercicio 3: Simulación de Vulnerabilidad y Remediación](#ejercicio-3-simulación-de-vulnerabilidad-y-remediación)
4. [Ejercicio 4: Seguridad en Entornos Virtualizados](#ejercicio-4-seguridad-en-entornos-virtualizados)
5. [Ejercicios Adicionales (Opcional)](#ejercicios-adicionales-opcional)

---

## EJERCICIO 1: ESCANEO DE CONFIGURACIONES INSEGURAS

### Objetivo
Identificar buckets S3 públicos utilizando un script Python que audita las configuraciones de acceso.

### Duración Estimada
30-45 minutos

### Prerrequisitos
- Entorno configurado según [SETUP.md](SETUP.md)
- Cuenta AWS o LocalStack funcionando
- Scripts de la clase descargados

---

### Parte A: Crear Buckets de Prueba

#### Paso 1: Crear Bucket Privado (Seguro)

```bash
# Opción 1: AWS Real
aws s3 mb s3://mi-bucket-privado-lab-$(date +%s)

# Opción 2: LocalStack
aws --endpoint-url=http://localhost:4566 s3 mb s3://mi-bucket-privado-lab

# Guardar el nombre del bucket para uso posterior
PRIVATE_BUCKET="mi-bucket-privado-lab-$(date +%s)"
```

#### Paso 2: Crear Bucket Público (Inseguro - Solo para demostración)

```bash
# Opción 1: AWS Real
BUCKET_NAME="mi-bucket-publico-lab-$(date +%s)"
aws s3 mb s3://${BUCKET_NAME}

# Hacer el bucket público (INSEGURO - solo para laboratorio)
aws s3api put-bucket-acl --bucket ${BUCKET_NAME} --acl public-read

# Opción 2: LocalStack
aws --endpoint-url=http://localhost:4566 s3 mb s3://mi-bucket-publico-lab
aws --endpoint-url=http://localhost:4566 s3api put-bucket-acl --bucket mi-bucket-publico-lab --acl public-read
```

#### Paso 3: Subir Archivo de Prueba

```bash
# Crear archivo de prueba
echo "Este es un archivo de prueba" > test-file.txt

# Subir al bucket público
aws s3 cp test-file.txt s3://${BUCKET_NAME}/

# Verificar que es accesible públicamente
curl https://${BUCKET_NAME}.s3.amazonaws.com/test-file.txt
```

**Salida esperada:**
```
Este es un archivo de prueba
```

---

### Parte B: Ejecutar Script de Auditoría

#### Paso 1: Revisar el Código

```bash
# Abrir el script en tu editor
code scripts/detect_public_buckets.py

# O ver con less
less scripts/detect_public_buckets.py
```

**Puntos clave a observar:**
1. Cómo se conecta a AWS usando boto3
2. Cómo verifica las ACLs del bucket
3. Cómo identifica permisos públicos
4. Cómo genera el reporte

#### Paso 2: Ejecutar el Script

```bash
# Asegurarse de estar en el directorio clase7
cd clase7

# Activar entorno virtual si no está activo
source venv/bin/activate

# Ejecutar el script
python scripts/detect_public_buckets.py
```

**Salida esperada:**
```
======================================================================
AUDITOR DE SEGURIDAD S3 - CLASE 7
UTN - Laboratorio de Ciberseguridad
======================================================================
[+] Conexión establecida con AWS S3
[+] Fecha de auditoría: 2025-10-24 15:30:45
----------------------------------------------------------------------
[+] Se encontraron 2 buckets en la cuenta

[*] Iniciando auditoría de seguridad...
----------------------------------------------------------------------

======================================================================
RESUMEN DE AUDITORÍA DE SEGURIDAD S3
======================================================================

[+] Total de buckets analizados: 2
[!] Buckets públicos encontrados: 1
[!] Buckets con riesgo CRÍTICO: 1
[!] Buckets con riesgo ALTO: 0

----------------------------------------------------------------------
BUCKETS PÚBLICOS DETECTADOS:
----------------------------------------------------------------------

[!] Bucket: mi-bucket-publico-lab-1234567890
    Nivel de riesgo: CRÍTICO
    Permisos ACL públicos:
      - AllUsers: READ
    [!] ADVERTENCIA: Bloqueo de acceso público NO configurado

======================================================================
RECOMENDACIONES:
======================================================================

1. Revisar y eliminar permisos públicos innecesarios
2. Habilitar 'Block Public Access' en todos los buckets
...
```

#### Paso 3: Analizar Resultados

```bash
# El script genera un archivo JSON con los resultados
cat audit_results.json | python -m json.tool

# Analizar el contenido
# - ¿Cuántos buckets públicos se encontraron?
# - ¿Qué permisos tienen?
# - ¿Cuál es el nivel de riesgo?
```

---

### Parte C: Documentar Hallazgos

#### Crear Reporte del Ejercicio 1

Crea un archivo `ejercicio1_reporte.md`:

```markdown
# EJERCICIO 1 - REPORTE DE AUDITORÍA S3

## Información General
- Fecha: [FECHA]
- Estudiante/Grupo: [NOMBRE]
- Región: [REGIÓN]

## Buckets Analizados
- Total: [NÚMERO]
- Públicos: [NÚMERO]

## Hallazgos

### Bucket 1: [NOMBRE]
- **Estado:** Público / Privado
- **Riesgo:** Crítico / Alto / Medio / Bajo
- **Permisos:**
  - ACL: [DETALLES]
  - Política: [DETALLES]
- **Bloqueo de acceso público:** Habilitado / Deshabilitado

## Capturas de Pantalla
[Insertar capturas de la ejecución del script]

## Análisis
[Explicar qué hace inseguro al bucket público]

## Conclusiones
[Lecciones aprendidas]
```

---

## EJERCICIO 2: POLÍTICA IAM SEGURA

### Objetivo
Crear y aplicar una política IAM que implemente el principio de mínimo privilegio y fuerce conexiones seguras.

### Duración Estimada
30 minutos

---

### Parte A: Analizar Política de Ejemplo

#### Paso 1: Revisar la Política

```bash
# Ver la política de ejemplo
cat templates/IAM_policy_example.json
```

**Análisis de la política:**

```json
{
  "Statement": [
    {
      "Sid": "AllowSpecificActionsOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      // ¿Qué permite hacer?
      // Solo GET y PUT, no DELETE ni modificar permisos

      "Resource": "arn:aws:s3:::empresa-segura/*",
      // Solo objetos dentro del bucket, no el bucket mismo

      "Condition": {
        "Bool": {"aws:SecureTransport": "true"}
        // FUERZA el uso de HTTPS (TLS)
      }
    }
  ]
}
```

**Preguntas para reflexionar:**
1. ¿Qué acciones permite esta política?
2. ¿Qué acciones NO permite?
3. ¿Qué pasa si intento acceder sin HTTPS?
4. ¿Es esto mínimo privilegio? ¿Por qué?

---

### Parte B: Crear Usuario IAM con Política Restrictiva

#### Paso 1: Crear Usuario de Prueba

```bash
# Crear usuario IAM
aws iam create-user --user-name lab-restricted-user

# Crear clave de acceso
aws iam create-access-key --user-name lab-restricted-user > user-credentials.json

# Ver credenciales (GUARDAR EN LUGAR SEGURO)
cat user-credentials.json
```

**¡IMPORTANTE!** Guarda estas credenciales de forma segura y elimínalas al terminar el laboratorio.

#### Paso 2: Crear y Adjuntar Política

```bash
# Primero, modificar la política con el nombre de tu bucket
# Editar templates/IAM_policy_example.json y reemplazar "empresa-segura" con tu bucket

# Crear la política
aws iam create-policy \
  --policy-name LabSecureS3Policy \
  --policy-document file://templates/IAM_policy_example.json

# Obtener el ARN de la política (aparecerá en la salida anterior)
POLICY_ARN="arn:aws:iam::ACCOUNT_ID:policy/LabSecureS3Policy"

# Adjuntar política al usuario
aws iam attach-user-policy \
  --user-name lab-restricted-user \
  --policy-arn ${POLICY_ARN}
```

---

### Parte C: Probar la Política

#### Paso 1: Configurar Perfil con Credenciales Restrictivas

```bash
# Extraer credenciales del JSON
ACCESS_KEY=$(jq -r '.AccessKey.AccessKeyId' user-credentials.json)
SECRET_KEY=$(jq -r '.AccessKey.SecretAccessKey' user-credentials.json)

# Configurar perfil
aws configure --profile restricted-user
# Ingresar las credenciales cuando se solicite
```

#### Paso 2: Probar Acceso Permitido

```bash
# Intentar subir un archivo (DEBERÍA FUNCIONAR con HTTPS)
echo "Prueba de política" > test-policy.txt
aws s3 cp test-policy.txt s3://${PRIVATE_BUCKET}/ --profile restricted-user

# Intentar descargar (DEBERÍA FUNCIONAR)
aws s3 cp s3://${PRIVATE_BUCKET}/test-policy.txt downloaded.txt --profile restricted-user
```

#### Paso 3: Probar Acceso Denegado

```bash
# Intentar eliminar (DEBERÍA FALLAR - no está en la política)
aws s3 rm s3://${PRIVATE_BUCKET}/test-policy.txt --profile restricted-user

# Salida esperada:
# An error occurred (AccessDenied) when calling the DeleteObject operation

# Intentar listar buckets (DEBERÍA FALLAR)
aws s3 ls --profile restricted-user

# Intentar modificar ACL (DEBERÍA FALLAR)
aws s3api put-bucket-acl --bucket ${PRIVATE_BUCKET} --acl public-read --profile restricted-user
```

#### Paso 4: Documentar Resultados

Completa una tabla como esta:

| Acción | Comando | Resultado Esperado | Resultado Obtenido | ¿Por qué? |
|--------|---------|--------------------|--------------------|-----------|
| Subir archivo | s3 cp | Éxito | [TU RESULTADO] | Permitido por política |
| Descargar | s3 cp (download) | Éxito | [TU RESULTADO] | Permitido por política |
| Eliminar | s3 rm | Denegado | [TU RESULTADO] | NO en la política |
| Listar buckets | s3 ls | Denegado | [TU RESULTADO] | NO en la política |

---

## EJERCICIO 3: SIMULACIÓN DE VULNERABILIDAD Y REMEDIACIÓN

### Objetivo
Crear una vulnerabilidad intencional, detectarla con herramientas y remediarla aplicando controles de seguridad.

### Duración Estimada
45 minutos

---

### Parte A: Crear Vulnerabilidad

#### Paso 1: Crear Bucket Vulnerable

```bash
# Crear bucket
VULN_BUCKET="bucket-vulnerable-lab-$(date +%s)"
aws s3 mb s3://${VULN_BUCKET}

# Hacer público (VULNERABILIDAD)
aws s3api put-bucket-acl --bucket ${VULN_BUCKET} --acl public-read-write

# Subir datos "sensibles" de prueba
cat > datos-sensibles.txt << EOF
Usuario: admin
Password: Admin123!
API Key: sk-1234567890abcdef
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
EOF

aws s3 cp datos-sensibles.txt s3://${VULN_BUCKET}/
```

#### Paso 2: Verificar que es Públicamente Accesible

```bash
# Intentar acceder sin credenciales
curl https://${VULN_BUCKET}.s3.amazonaws.com/datos-sensibles.txt

# DEBERÍA funcionar y mostrar el contenido
# ESTO ES UNA BRECHA DE SEGURIDAD CRÍTICA
```

**Captura esta salida para tu reporte.**

---

### Parte B: Detectar Vulnerabilidad

#### Paso 1: Ejecutar Script de Auditoría

```bash
# Ejecutar el auditor
python scripts/detect_public_buckets.py

# Debería detectar el bucket vulnerable
```

**Salida esperada:**
```
[!] Bucket público detectado: bucket-vulnerable-lab-1234567890
    Nivel de riesgo: CRÍTICO
    Permisos ACL públicos:
      - AllUsers: READ
      - AllUsers: WRITE
```

#### Paso 2: Ejecutar Escaneo Manual

```bash
# Verificar ACL manualmente
aws s3api get-bucket-acl --bucket ${VULN_BUCKET}

# Verificar si tiene bloqueo de acceso público
aws s3api get-public-access-block --bucket ${VULN_BUCKET}

# Si no tiene, verás:
# An error occurred (NoSuchPublicAccessBlockConfiguration)
```

---

### Parte C: Remediar la Vulnerabilidad

#### Paso 1: Remover Permisos Públicos

```bash
# Opción 1: Usar ACL privada
aws s3api put-bucket-acl --bucket ${VULN_BUCKET} --acl private

# Verificar
aws s3api get-bucket-acl --bucket ${VULN_BUCKET}
```

#### Paso 2: Habilitar Block Public Access

```bash
# Habilitar todas las protecciones de Block Public Access
aws s3api put-public-access-block \
  --bucket ${VULN_BUCKET} \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Verificar
aws s3api get-public-access-block --bucket ${VULN_BUCKET}
```

#### Paso 3: Aplicar Política de Bucket Segura

```bash
# Editar templates/bucket_policy_secure.json
# Reemplazar BUCKET-NAME con ${VULN_BUCKET}

# Aplicar política
aws s3api put-bucket-policy \
  --bucket ${VULN_BUCKET} \
  --policy file://templates/bucket_policy_secure.json
```

#### Paso 4: Habilitar Cifrado

```bash
# Habilitar cifrado en reposo (SSE-S3)
aws s3api put-bucket-encryption \
  --bucket ${VULN_BUCKET} \
  --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

# Verificar
aws s3api get-bucket-encryption --bucket ${VULN_BUCKET}
```

#### Paso 5: Habilitar Logging

```bash
# Crear bucket para logs
LOG_BUCKET="${VULN_BUCKET}-logs"
aws s3 mb s3://${LOG_BUCKET}

# Habilitar logging
aws s3api put-bucket-logging \
  --bucket ${VULN_BUCKET} \
  --bucket-logging-status \
    "{\"LoggingEnabled\": {\"TargetBucket\": \"${LOG_BUCKET}\", \"TargetPrefix\": \"access-logs/\"}}"
```

---

### Parte D: Verificar Remediación

#### Paso 1: Re-ejecutar Auditoría

```bash
# Ejecutar nuevamente el script
python scripts/detect_public_buckets.py

# Ahora NO debería reportar el bucket como público
```

#### Paso 2: Verificar Acceso Público Bloqueado

```bash
# Intentar acceder sin credenciales (DEBERÍA FALLAR)
curl https://${VULN_BUCKET}.s3.amazonaws.com/datos-sensibles.txt

# Salida esperada: Access Denied
```

#### Paso 3: Documentar el Proceso

Crear documento `ejercicio3_remediacion.md`:

```markdown
# EJERCICIO 3 - REMEDIACIÓN DE VULNERABILIDAD

## 1. Vulnerabilidad Identificada
- **Bucket:** [NOMBRE]
- **Problema:** Acceso público de lectura/escritura
- **Riesgo:** CRÍTICO
- **Evidencia:** [CAPTURA DE CURL EXITOSO]

## 2. Detección
- **Herramienta:** detect_public_buckets.py
- **Hallazgos:** [DESCRIBIR]
- **Captura:** [SALIDA DEL SCRIPT]

## 3. Remediación Aplicada

### 3.1 ACL Privada
```bash
[COMANDO USADO]
```
Resultado: [DESCRIBIR]

### 3.2 Block Public Access
```bash
[COMANDO USADO]
```
Resultado: [DESCRIBIR]

### 3.3 Política de Bucket
[POLÍTICA APLICADA]

### 3.4 Cifrado
[CONFIGURACIÓN]

### 3.5 Logging
[CONFIGURACIÓN]

## 4. Verificación Post-Remediación
- **Acceso público:** [BLOQUEADO ✓]
- **Auditoría:** [CAPTURA]
- **Curl test:** [Access Denied ✓]

## 5. Conclusiones
[LECCIONES APRENDIDAS]
```

---

## EJERCICIO 4: SEGURIDAD EN ENTORNOS VIRTUALIZADOS

### Objetivo
Auditar seguridad de máquinas virtuales y aplicar hardening básico.

### Duración Estimada
60-90 minutos

---

### Parte A: Configurar Entorno Virtual

#### Paso 1: Crear Red Interna

```bash
# VirtualBox - crear red NAT
VBoxManage natnetwork add --netname LabNetwork --network "192.168.56.0/24" --enable

# Verificar
VBoxManage list natnetworks
```

#### Paso 2: Crear VMs

**VM 1 - Ubuntu Server (Target):**
```bash
# Crear VM
VBoxManage createvm --name "Ubuntu-Target" --ostype Ubuntu_64 --register

# Configurar memoria y CPU
VBoxManage modifyvm "Ubuntu-Target" --memory 2048 --cpus 2

# Crear disco virtual
VBoxManage createhd --filename ~/VirtualBox\ VMs/Ubuntu-Target/Ubuntu-Target.vdi --size 20480

# Asociar disco
VBoxManage storagectl "Ubuntu-Target" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "Ubuntu-Target" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium ~/VirtualBox\ VMs/Ubuntu-Target/Ubuntu-Target.vdi

# Configurar red
VBoxManage modifyvm "Ubuntu-Target" --nic1 nat --nic2 intnet --intnet2 LabNetwork

# Instalar Ubuntu Server (proceso manual con ISO)
```

**VM 2 - Kali Linux (Auditor):**
```bash
# Descargar imagen pre-construida de Kali
# https://www.kali.org/get-kali/#kali-virtual-machines

# Importar
VBoxManage import kali-linux-2023.3-virtualbox-amd64.ova --vsys 0 --vmname "Kali-Auditor"

# Configurar red
VBoxManage modifyvm "Kali-Auditor" --nic2 intnet --intnet2 LabNetwork
```

---

### Parte B: Auditoría de Seguridad

#### Paso 1: Iniciar VMs y Verificar Conectividad

En **Ubuntu-Target:**
```bash
# Configurar IP estática en interfaz interna
sudo ip addr add 192.168.56.10/24 dev enp0s8
sudo ip link set enp0s8 up

# Instalar servicios para prueba
sudo apt update
sudo apt install -y openssh-server apache2 mysql-server

# Verificar servicios activos
sudo systemctl status ssh
sudo systemctl status apache2
sudo systemctl status mysql
```

En **Kali-Auditor:**
```bash
# Configurar IP
sudo ip addr add 192.168.56.20/24 dev eth1
sudo ip link set eth1 up

# Verificar conectividad
ping -c 4 192.168.56.10
```

#### Paso 2: Escaneo con Nmap

En **Kali-Auditor:**
```bash
# Escaneo básico
nmap 192.168.56.10

# Escaneo de servicios y versiones
nmap -sS -sV 192.168.56.10

# Escaneo completo con detección de OS
nmap -A -T4 192.168.56.10 -oN scan_results.txt

# Ver resultados
cat scan_results.txt
```

**Salida esperada:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.33
```

#### Paso 3: Análisis de Vulnerabilidades

```bash
# Escaneo de vulnerabilidades con scripts NSE
nmap --script vuln 192.168.56.10 -oN vuln_scan.txt

# Escaneo de configuraciones inseguras SSH
nmap --script ssh-auth-methods,ssh2-enum-algos 192.168.56.10
```

#### Paso 4: Documentar Hallazgos

Crear tabla de servicios:

| Puerto | Servicio | Versión | Vulnerabilidades | Riesgo |
|--------|----------|---------|------------------|--------|
| 22 | SSH | OpenSSH 8.9p1 | Ninguna conocida | Bajo |
| 80 | HTTP | Apache 2.4.52 | [INVESTIGAR CVEs] | ? |
| 3306 | MySQL | 8.0.33 | Expuesto externamente | Alto |

---

### Parte C: Hardening y Remediación

En **Ubuntu-Target:**

#### Paso 1: Configurar Firewall

```bash
# Instalar y configurar UFW
sudo apt install -y ufw

# Denegar todo por defecto
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir solo SSH
sudo ufw allow 22/tcp

# Habilitar firewall
sudo ufw enable

# Verificar
sudo ufw status verbose
```

#### Paso 2: Hardening de SSH

```bash
# Backup de configuración
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Editar configuración
sudo nano /etc/ssh/sshd_config

# Aplicar cambios:
# PermitRootLogin no
# PasswordAuthentication no (después de configurar SSH key)
# Port 2222 (opcional - cambiar puerto por defecto)
# AllowUsers [tu_usuario]

# Reiniciar SSH
sudo systemctl restart sshd
```

#### Paso 3: Asegurar MySQL

```bash
# Ejecutar script de seguridad de MySQL
sudo mysql_secure_installation

# Responder:
# - Set root password? [Y]
# - Remove anonymous users? [Y]
# - Disallow root login remotely? [Y]
# - Remove test database? [Y]
# - Reload privilege tables? [Y]

# Configurar MySQL para escuchar solo en localhost
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# Verificar línea:
# bind-address = 127.0.0.1

# Reiniciar
sudo systemctl restart mysql
```

#### Paso 4: Deshabilitar Servicios Innecesarios

```bash
# Listar servicios activos
systemctl list-units --type=service --state=running

# Si Apache no es necesario, deshabilitarlo
sudo systemctl stop apache2
sudo systemctl disable apache2
```

---

### Parte D: Verificación Post-Hardening

En **Kali-Auditor:**

```bash
# Re-escanear
nmap -sS -sV 192.168.56.10

# Verificar que MySQL ya no es accesible externamente
nmap -p 3306 192.168.56.10
# Debería mostrar: filtered o closed

# Verificar solo SSH accesible
nmap -p 22,80,3306,443 192.168.56.10
```

---

### Parte E: Snapshots y Respaldo

#### Paso 1: Crear Snapshot Cifrado

```bash
# Detener VM
VBoxManage controlvm "Ubuntu-Target" poweroff

# Crear snapshot
VBoxManage snapshot "Ubuntu-Target" take "post-hardening" --description "VM después de aplicar hardening"

# Exportar VM
VBoxManage export "Ubuntu-Target" -o ubuntu-target-hardened.ova

# (Opcional) Cifrar con GPG
gpg --symmetric --cipher-algo AES256 ubuntu-target-hardened.ova
```

#### Paso 2: Documentar Configuración

Crear archivo `vm-hardening-checklist.md`:

```markdown
# CHECKLIST DE HARDENING - UBUNTU TARGET

## Configuración de Red
- [x] Firewall UFW habilitado
- [x] Política por defecto: denegar incoming
- [x] Solo puerto 22 permitido

## Servicios
- [x] SSH configurado de forma segura
  - [x] PermitRootLogin: no
  - [x] Clave SSH requerida
- [x] MySQL solo en localhost
- [x] Apache deshabilitado (no necesario)

## Sistema Operativo
- [x] Sistema actualizado
- [x] Servicios innecesarios deshabilitados
- [x] Logs configurados

## Respaldo
- [x] Snapshot creado: post-hardening
- [x] Exportación realizada
- [ ] Cifrado de snapshot (opcional)

## Verificación
- [x] Nmap post-hardening ejecutado
- [x] Solo servicios necesarios expuestos
- [x] Documentación completa
```

---

## EJERCICIOS ADICIONALES (OPCIONAL)

### Ejercicio 5: Auditoría de Security Groups

```bash
# Ejecutar script de Security Groups
python scripts/check_security_groups.py

# O especificar región
python scripts/check_security_groups.py us-west-2

# Analizar resultados
cat sg_audit_results.json | jq '.findings[] | select(.severity == "CRÍTICO")'
```

### Ejercicio 6: Auditoría de Usuarios IAM

```bash
# Ejecutar auditoría IAM
python scripts/audit_iam_users.py

# Revisar usuarios sin MFA
cat iam_audit_results.json | jq '.users[] | select(.mfa_enabled == false)'

# Revisar claves antiguas
cat iam_audit_results.json | jq '.users[].findings[] | select(.type == "OLD_ACCESS_KEY")'
```

### Ejercicio 7: Implementar AWS Config Rules

```bash
# Crear regla para detectar buckets públicos
aws configservice put-config-rule --config-rule file://aws-config-rules/s3-bucket-public-read-prohibited.json

# Crear regla para MFA en root
aws configservice put-config-rule --config-rule file://aws-config-rules/root-account-mfa-enabled.json

# Ver evaluación de cumplimiento
aws configservice describe-compliance-by-config-rule
```

---

## ENTREGA FINAL

### Estructura del Reporte

Entregar un PDF con:

1. **Carátula**
   - Título: Laboratorio Clase 7 - Seguridad Cloud y Virtualización
   - Nombre/Grupo
   - Fecha

2. **Índice**

3. **Introducción**
   - Objetivos
   - Alcance
   - Entorno utilizado

4. **Ejercicio 1: Auditoría S3**
   - Procedimiento
   - Hallazgos
   - Capturas de pantalla

5. **Ejercicio 2: Políticas IAM**
   - Políticas creadas
   - Pruebas realizadas
   - Análisis de resultados

6. **Ejercicio 3: Remediación**
   - Vulnerabilidad inicial
   - Proceso de remediación
   - Verificación

7. **Ejercicio 4: Virtualización**
   - Topología de red
   - Hallazgos de auditoría
   - Hardening aplicado
   - Verificación post-hardening

8. **Conclusiones**
   - Lecciones aprendidas
   - Mejores prácticas identificadas
   - Recomendaciones

9. **Anexos**
   - Código de scripts
   - Salidas completas de comandos
   - Políticas JSON

### Plantilla de Reporte

Ver: [templates/reporte_template.md](../templates/reporte_template.md)

---

## LIMPIEZA Y CLEANUP

**¡IMPORTANTE!** Al terminar el laboratorio, eliminar recursos para evitar costos:

```bash
# Eliminar buckets y contenido
aws s3 rb s3://${VULN_BUCKET} --force
aws s3 rb s3://${LOG_BUCKET} --force
aws s3 rb s3://${PRIVATE_BUCKET} --force
aws s3 rb s3://${BUCKET_NAME} --force

# Eliminar usuario IAM y credenciales
aws iam detach-user-policy --user-name lab-restricted-user --policy-arn ${POLICY_ARN}
aws iam delete-access-key --user-name lab-restricted-user --access-key-id ${ACCESS_KEY}
aws iam delete-user --user-name lab-restricted-user

# Eliminar política
aws iam delete-policy --policy-arn ${POLICY_ARN}

# Detener LocalStack
docker-compose down

# (Opcional) Eliminar VMs
VBoxManage unregistervm "Ubuntu-Target" --delete
VBoxManage unregistervm "Kali-Auditor" --delete
```

---

**Actualizado:** Octubre 2025
**Autor:** UTN - Laboratorio de Ciberseguridad
