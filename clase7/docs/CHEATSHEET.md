# CHEATSHEET - SEGURIDAD CLOUD
## Comandos y Referencias Rápidas

---

## ÍNDICE

1. [AWS CLI Esenciales](#aws-cli-esenciales)
2. [boto3 Python](#boto3-python)
3. [S3 Security](#s3-security)
4. [IAM Security](#iam-security)
5. [EC2 Security](#ec2-security)
6. [VPC y Network](#vpc-y-network)
7. [Monitoring y Logging](#monitoring-y-logging)
8. [Docker Security](#docker-security)
9. [Kubernetes Security](#kubernetes-security)
10. [Herramientas de Auditoría](#herramientas-de-auditoría)

---

## AWS CLI ESENCIALES

### Configuración Inicial

```bash
# Configurar credenciales
aws configure
aws configure --profile myprofile

# Verificar configuración
aws configure list
aws sts get-caller-identity

# Variables de entorno
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
export AWS_PROFILE="myprofile"

# Limpiar credenciales cache
rm ~/.aws/cli/cache/*
```

### Comandos Básicos

```bash
# Listar regiones
aws ec2 describe-regions --output table

# Obtener Account ID
aws sts get-caller-identity --query Account --output text

# Listar todos los servicios disponibles
aws help

# Obtener ayuda de un servicio
aws s3 help
aws s3 cp help
```

---

## BOTO3 PYTHON

### Setup Básico

```python
import boto3
from botocore.exceptions import ClientError

# Cliente con credenciales por defecto
s3 = boto3.client('s3')

# Cliente con región específica
s3 = boto3.client('s3', region_name='us-west-2')

# Cliente con credenciales explícitas
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIA...',
    aws_secret_access_key='...',
    region_name='us-east-1'
)

# Cliente con perfil
session = boto3.Session(profile_name='myprofile')
s3 = session.client('s3')

# Resource vs Client
s3_client = boto3.client('s3')  # API de bajo nivel
s3_resource = boto3.resource('s3')  # API de alto nivel
```

### Manejo de Errores

```python
try:
    response = s3.get_bucket_acl(Bucket='my-bucket')
except ClientError as e:
    error_code = e.response['Error']['Code']
    error_message = e.response['Error']['Message']

    if error_code == 'NoSuchBucket':
        print("Bucket no existe")
    elif error_code == 'AccessDenied':
        print("Acceso denegado")
    else:
        print(f"Error: {error_message}")
```

---

## S3 SECURITY

### Auditoría de Buckets

```bash
# Listar todos los buckets
aws s3 ls

# Listar contenido de un bucket
aws s3 ls s3://bucket-name/
aws s3 ls s3://bucket-name/ --recursive
aws s3 ls s3://bucket-name/ --human-readable --summarize

# Sin credenciales (para buckets públicos)
aws s3 ls s3://bucket-name/ --no-sign-request

# Obtener ACL
aws s3api get-bucket-acl --bucket bucket-name

# Obtener política
aws s3api get-bucket-policy --bucket bucket-name

# Obtener Block Public Access
aws s3api get-public-access-block --bucket bucket-name

# Obtener cifrado
aws s3api get-bucket-encryption --bucket bucket-name

# Obtener versionado
aws s3api get-bucket-versioning --bucket bucket-name

# Obtener logging
aws s3api get-bucket-logging --bucket bucket-name
```

### Hardening de Buckets

```bash
# Cambiar ACL a privada
aws s3api put-bucket-acl --bucket bucket-name --acl private

# Habilitar Block Public Access (todas las opciones)
aws s3api put-public-access-block \
  --bucket bucket-name \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Habilitar cifrado SSE-S3
aws s3api put-bucket-encryption \
  --bucket bucket-name \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Habilitar cifrado SSE-KMS
aws s3api put-bucket-encryption \
  --bucket bucket-name \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:..."}}]}'

# Habilitar versionado
aws s3api put-bucket-versioning \
  --bucket bucket-name \
  --versioning-configuration Status=Enabled

# Habilitar logging
aws s3api put-bucket-logging \
  --bucket bucket-name \
  --bucket-logging-status \
    '{"LoggingEnabled":{"TargetBucket":"log-bucket","TargetPrefix":"logs/"}}'

# Política de bucket segura
aws s3api put-bucket-policy --bucket bucket-name --policy file://secure-policy.json
```

### Python boto3

```python
import boto3

s3 = boto3.client('s3')

# Auditar bucket
def audit_bucket(bucket_name):
    # ACL
    acl = s3.get_bucket_acl(Bucket=bucket_name)
    for grant in acl['Grants']:
        grantee = grant.get('Grantee', {})
        if grantee.get('Type') == 'Group':
            uri = grantee.get('URI', '')
            if 'AllUsers' in uri:
                print(f"[!] Bucket público: {bucket_name}")

    # Cifrado
    try:
        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        print(f"[+] Cifrado habilitado")
    except:
        print(f"[!] Cifrado NO habilitado")

    # Block Public Access
    try:
        block = s3.get_public_access_block(Bucket=bucket_name)
        config = block['PublicAccessBlockConfiguration']
        if all(config.values()):
            print(f"[+] Block Public Access completamente habilitado")
        else:
            print(f"[!] Block Public Access parcial o deshabilitado")
    except:
        print(f"[!] Block Public Access NO configurado")
```

---

## IAM SECURITY

### Auditoría de Usuarios

```bash
# Listar usuarios
aws iam list-users

# Obtener usuario actual
aws iam get-user

# Listar políticas de un usuario
aws iam list-user-policies --user-name username
aws iam list-attached-user-policies --user-name username

# Obtener política inline
aws iam get-user-policy --user-name username --policy-name policy-name

# Obtener política administrada
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/PolicyName
aws iam get-policy-version --policy-arn arn --version-id v1

# Listar claves de acceso
aws iam list-access-keys --user-name username

# Último uso de clave de acceso
aws iam get-access-key-last-used --access-key-id AKIA...

# Listar dispositivos MFA
aws iam list-mfa-devices --user-name username

# Obtener política de contraseñas
aws iam get-account-password-policy
```

### Gestión de Usuarios

```bash
# Crear usuario
aws iam create-user --user-name newuser

# Crear clave de acceso
aws iam create-access-key --user-name username

# Rotar clave de acceso
aws iam update-access-key --user-name username --access-key-id AKIA... --status Inactive
aws iam create-access-key --user-name username
aws iam delete-access-key --user-name username --access-key-id AKIA...

# Adjuntar política
aws iam attach-user-policy \
  --user-name username \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Crear política inline
aws iam put-user-policy \
  --user-name username \
  --policy-name PolicyName \
  --policy-document file://policy.json

# Habilitar MFA (requiere pasos adicionales con dispositivo)
aws iam enable-mfa-device \
  --user-name username \
  --serial-number arn:aws:iam::123456789012:mfa/username \
  --authentication-code-1 123456 \
  --authentication-code-2 789012
```

### Roles y AssumeRole

```bash
# Listar roles
aws iam list-roles

# Obtener rol
aws iam get-role --role-name RoleName

# Asumir rol
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/RoleName \
  --role-session-name SessionName

# Usar credenciales temporales
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
```

---

## EC2 SECURITY

### Security Groups

```bash
# Listar Security Groups
aws ec2 describe-security-groups

# Obtener Security Group específico
aws ec2 describe-security-groups --group-ids sg-12345678

# Buscar Security Groups con puerto 22 abierto
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table

# Agregar regla
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 192.0.2.0/24

# Eliminar regla
aws ec2 revoke-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Crear Security Group restrictivo
aws ec2 create-security-group \
  --group-name RestrictiveSG \
  --description "Security group with minimal access" \
  --vpc-id vpc-12345678

# Agregar solo HTTPS desde CloudFront
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --ip-permissions \
    IpProtocol=tcp,FromPort=443,ToPort=443,PrefixListIds=[{PrefixListId=pl-3b927c52}]
```

### Instancias EC2

```bash
# Listar instancias
aws ec2 describe-instances

# Instancias en ejecución
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PublicIpAddress]' \
  --output table

# Obtener IMDSv2 status
aws ec2 describe-instances --instance-ids i-1234567890abcdef0 \
  --query 'Reservations[0].Instances[0].MetadataOptions'

# Requerir IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Obtener volúmenes
aws ec2 describe-volumes

# Verificar cifrado de volumen
aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0 \
  --query 'Volumes[0].Encrypted'

# Crear snapshot cifrado
aws ec2 create-snapshot \
  --volume-id vol-1234567890abcdef0 \
  --description "Encrypted snapshot" \
  --encrypted

# Copiar snapshot con cifrado
aws ec2 copy-snapshot \
  --source-region us-west-2 \
  --source-snapshot-id snap-1234567890abcdef0 \
  --destination-region us-east-1 \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

---

## VPC Y NETWORK

### VPC Flow Logs

```bash
# Crear VPC Flow Log
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs

# Listar Flow Logs
aws ec2 describe-flow-logs

# Ver logs
aws logs tail /aws/vpc/flowlogs --follow
```

### Network ACLs

```bash
# Listar NACLs
aws ec2 describe-network-acls

# Crear regla de NACL (denegar SSH desde Internet)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-12345678 \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=22,To=22 \
  --cidr-block 0.0.0.0/0 \
  --rule-action deny
```

---

## MONITORING Y LOGGING

### CloudTrail

```bash
# Crear trail
aws cloudtrail create-trail \
  --name MyTrail \
  --s3-bucket-name my-trail-bucket

# Iniciar logging
aws cloudtrail start-logging --name MyTrail

# Verificar estado
aws cloudtrail get-trail-status --name MyTrail

# Buscar eventos
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket

# Eventos de los últimos 7 días
aws cloudtrail lookup-events \
  --start-time $(date -u -d '7 days ago' +%s) \
  --max-results 50
```

### CloudWatch

```bash
# Crear alarma para CPU alta
aws cloudwatch put-metric-alarm \
  --alarm-name HighCPU \
  --alarm-description "Alert when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=InstanceId,Value=i-1234567890abcdef0

# Ver métricas
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-1234567890abcdef0 \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average

# Ver logs
aws logs describe-log-groups
aws logs tail /aws/lambda/my-function --follow
```

### AWS Config

```bash
# Crear Config Recorder
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/config-role \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# Iniciar recorder
aws configservice start-configuration-recorder --configuration-recorder-name default

# Agregar regla (S3 bucket público)
aws configservice put-config-rule \
  --config-rule file://s3-bucket-public-read-prohibited.json

# Ver compliance
aws configservice describe-compliance-by-config-rule \
  --config-rule-names s3-bucket-public-read-prohibited
```

---

## DOCKER SECURITY

### Escaneo de Imágenes

```bash
# Escanear con Trivy
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myapp:1.0

# Escanear con Clair
clairctl analyze myapp:1.0

# Escanear con Snyk
snyk container test nginx:latest
snyk container test myapp:1.0 --severity-threshold=high
```

### Mejores Prácticas

```bash
# Construir con usuario no-root
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

# Crear usuario no-privilegiado
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Instalar dependencias
RUN apt-get update && apt-get install -y python3

# Cambiar a usuario no-root
USER appuser

# Aplicación
WORKDIR /app
COPY --chown=appuser:appuser . .

CMD ["python3", "app.py"]
EOF

# Construir imagen
docker build -t myapp:secure .

# Ejecutar contenedor con read-only filesystem
docker run --read-only --tmpfs /tmp myapp:secure

# Ejecutar con capabilities limitadas
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp:secure

# Ejecutar sin privilegios
docker run --security-opt=no-new-privileges:true myapp:secure

# Limitar recursos
docker run \
  --memory="256m" \
  --cpus="0.5" \
  --pids-limit=100 \
  myapp:secure
```

### Docker Bench Security

```bash
# Descargar y ejecutar
docker run -it --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security
```

---

## KUBERNETES SECURITY

### Auditoría de Cluster

```bash
# Información del cluster
kubectl cluster-info
kubectl get nodes
kubectl version

# Namespaces
kubectl get namespaces

# Pods con privilegios
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.securityContext.privileged == true) | .metadata.name'

# Pods sin límites de recursos
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].resources.limits == null) | .metadata.name'

# Service Accounts
kubectl get serviceaccounts --all-namespaces

# Secrets
kubectl get secrets --all-namespaces
```

### Pod Security

```yaml
# Pod seguro ejemplo
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
        add:
          - NET_BIND_SERVICE

    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "250m"

    volumeMounts:
    - name: tmp
      mountPath: /tmp

  volumes:
  - name: tmp
    emptyDir: {}
```

### Network Policies

```yaml
# Denegar todo el tráfico por defecto
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Permitir solo tráfico necesario
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

### Kube-bench

```bash
# Ejecutar kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Ver resultados
kubectl logs -f job/kube-bench

# Eliminar job
kubectl delete job kube-bench
```

---

## HERRAMIENTAS DE AUDITORÍA

### ScoutSuite

```bash
# Instalar
pip install scoutsuite

# Ejecutar auditoría completa de AWS
scout aws --profile myprofile

# Solo servicios específicos
scout aws --services s3 iam ec2

# Con output HTML
scout aws --report-dir ./report
```

### Prowler

```bash
# Clonar repositorio
git clone https://github.com/prowler-cloud/prowler
cd prowler

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar auditoría completa
./prowler

# Solo checks específicos
./prowler -c check12 check13

# Exportar a JSON/CSV
./prowler -M json
./prowler -M csv

# Checks de CIS Benchmark
./prowler -g cislevel2
```

### CloudMapper

```bash
# Clonar repositorio
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper

# Instalar dependencias
pip install -r requirements.txt

# Configurar
python cloudmapper.py configure add-account --config-file config.json \
  --name MyAccount \
  --id 123456789012

# Recolectar datos
python cloudmapper.py collect --account MyAccount

# Generar reporte
python cloudmapper.py report --account MyAccount

# Generar visualización
python cloudmapper.py prepare --account MyAccount
python cloudmapper.py webserver
```

### AWS Security Hub

```bash
# Habilitar Security Hub
aws securityhub enable-security-hub

# Habilitar estándares
aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0

# Ver hallazgos
aws securityhub get-findings

# Filtrar por severidad
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
```

---

## ONE-LINERS ÚTILES

```bash
# Encontrar todos los buckets públicos
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I {} aws s3api get-bucket-acl --bucket {} --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text

# Usuarios sin MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} sh -c 'aws iam list-mfa-devices --user-name {} | grep -q SerialNumber || echo "No MFA: {}"'

# Security Groups con 0.0.0.0/0
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text

# Volúmenes EBS no cifrados
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].VolumeId' --output text

# Snapshots públicos
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?Public==`true`].SnapshotId' --output text

# Claves de acceso antiguas (>90 días)
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {} --query 'AccessKeyMetadata[*].[UserName,AccessKeyId,CreateDate]' --output text

# Instancias sin tags
aws ec2 describe-instances --query 'Reservations[*].Instances[?Tags==`null`].InstanceId' --output text
```

---

## REGEX Y GREP ÚTILES

```bash
# Buscar AWS Access Keys en código
grep -r -E 'AKIA[0-9A-Z]{16}' .

# Buscar contraseñas en código
grep -r -iE '(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']' .

# Buscar claves privadas
grep -r -E '-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----' .

# Buscar IPs en logs
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' logfile

# Buscar URLs
grep -oE 'https?://[^\s]+' file.txt
```

---

## SCRIPTS RÁPIDOS DE PYTHON

### Verificar Permisos S3

```python
import boto3

s3 = boto3.client('s3')

def check_public_buckets():
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    print(f"[!] Bucket público: {name}")
        except Exception as e:
            print(f"Error con {name}: {e}")

check_public_buckets()
```

### Verificar MFA de Usuarios

```python
import boto3

iam = boto3.client('iam')

def check_users_without_mfa():
    users = iam.list_users()['Users']
    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)
        if not mfa_devices['MFADevices']:
            print(f"[!] Usuario sin MFA: {username}")

check_users_without_mfa()
```

---

## REFERENCIAS RÁPIDAS

### Severidades de Vulnerabilidades

| Nivel | CVSS Score | Criterio |
|-------|------------|----------|
| CRÍTICO | 9.0-10.0 | Explotación trivial, alto impacto |
| ALTO | 7.0-8.9 | Fácil explotación, impacto significativo |
| MEDIO | 4.0-6.9 | Explotación moderada, impacto limitado |
| BAJO | 0.1-3.9 | Difícil explotación, bajo impacto |

### Ports Comunes

| Puerto | Servicio | Riesgo |
|--------|----------|--------|
| 22 | SSH | Alto si expuesto |
| 80 | HTTP | Medio |
| 443 | HTTPS | Bajo |
| 3306 | MySQL | Crítico si expuesto |
| 5432 | PostgreSQL | Crítico si expuesto |
| 6379 | Redis | Crítico si expuesto |
| 27017 | MongoDB | Crítico si expuesto |
| 3389 | RDP | Crítico si expuesto |

### Compliance Frameworks

- **CIS AWS Foundations Benchmark**: 50+ checks
- **PCI DSS**: Seguridad de datos de tarjetas
- **HIPAA**: Protección de datos de salud
- **SOC 2**: Controles de seguridad organizacionales
- **ISO 27001**: Sistema de gestión de seguridad
- **GDPR**: Protección de datos personales (UE)

---

© 2025 – UTN | Laboratorio de Ciberseguridad
