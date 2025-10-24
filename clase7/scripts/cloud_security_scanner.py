#!/usr/bin/env python3
"""
CLASE 7 - SEGURIDAD EN LA NUBE
Scanner Completo de Seguridad Cloud

Descripción:
Scanner comprehensivo que analiza múltiples aspectos de seguridad
en infraestructura AWS incluyendo S3, IAM, EC2, RDS, y Lambda.

Autor: UTN - Laboratorio de Ciberseguridad
Versión: 2.0
"""

import boto3
import json
import sys
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
from collections import defaultdict
import argparse


class CloudSecurityScanner:
    """
    Scanner comprehensivo de seguridad para AWS
    """

    def __init__(self, region='us-east-1', profile=None):
        """
        Inicializa el scanner con credenciales de AWS
        """
        try:
            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
            else:
                session = boto3.Session(region_name=region)

            self.region = region
            self.s3 = session.client('s3')
            self.iam = session.client('iam')
            self.ec2 = session.client('ec2')
            self.rds = session.client('rds')
            self.lambda_client = session.client('lambda')
            self.cloudtrail = session.client('cloudtrail')
            self.sts = session.client('sts')

            # Obtener identidad de la cuenta
            identity = self.sts.get_caller_identity()
            self.account_id = identity['Account']

            print(f"[+] Conexión establecida con AWS")
            print(f"[+] Account ID: {self.account_id}")
            print(f"[+] Región: {region}")
            print(f"[+] Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 70)

        except NoCredentialsError:
            print("[!] ERROR: No se encontraron credenciales de AWS")
            sys.exit(1)
        except Exception as e:
            print(f"[!] ERROR: {str(e)}")
            sys.exit(1)

    def scan_s3_security(self):
        """
        Escanea seguridad de buckets S3
        """
        print("\n[*] Escaneando buckets S3...")
        findings = []

        try:
            buckets = self.s3.list_buckets()

            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']

                # 1. Verificar ACL
                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        permission = grant.get('Permission', '')
                        uri = grantee.get('URI', '')

                        if 'AllUsers' in uri:
                            findings.append({
                                'service': 'S3',
                                'resource': bucket_name,
                                'severity': 'CRITICAL',
                                'issue': f'Bucket público con permiso {permission}',
                                'recommendation': 'Cambiar ACL a privada y habilitar Block Public Access'
                            })
                except ClientError:
                    pass

                # 2. Verificar cifrado
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'severity': 'HIGH',
                            'issue': 'Cifrado no habilitado',
                            'recommendation': 'Habilitar cifrado SSE-S3 o SSE-KMS'
                        })

                # 3. Verificar versionado
                try:
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'severity': 'MEDIUM',
                            'issue': 'Versionado no habilitado',
                            'recommendation': 'Habilitar versionado para protección contra eliminación'
                        })
                except ClientError:
                    pass

                # 4. Verificar logging
                try:
                    logging = self.s3.get_bucket_logging(Bucket=bucket_name)
                    if 'LoggingEnabled' not in logging:
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'severity': 'MEDIUM',
                            'issue': 'Logging no habilitado',
                            'recommendation': 'Habilitar access logging'
                        })
                except ClientError:
                    pass

                # 5. Verificar Block Public Access
                try:
                    block_config = self.s3.get_public_access_block(Bucket=bucket_name)
                    config = block_config.get('PublicAccessBlockConfiguration', {})

                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'severity': 'HIGH',
                            'issue': 'Block Public Access no completamente habilitado',
                            'recommendation': 'Habilitar todas las opciones de Block Public Access'
                        })
                except ClientError:
                    findings.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'severity': 'HIGH',
                        'issue': 'Block Public Access no configurado',
                        'recommendation': 'Configurar Block Public Access'
                    })

        except Exception as e:
            print(f"[!] Error escaneando S3: {str(e)}")

        return findings

    def scan_iam_security(self):
        """
        Escanea seguridad de IAM
        """
        print("\n[*] Escaneando configuración de IAM...")
        findings = []

        try:
            # 1. Verificar política de contraseñas
            try:
                policy = self.iam.get_account_password_policy()
                pwd_policy = policy.get('PasswordPolicy', {})

                if pwd_policy.get('MinimumPasswordLength', 0) < 14:
                    findings.append({
                        'service': 'IAM',
                        'resource': 'Account',
                        'severity': 'HIGH',
                        'issue': 'Longitud mínima de contraseña menor a 14 caracteres',
                        'recommendation': 'Establecer longitud mínima de 14 caracteres'
                    })

                if not pwd_policy.get('RequireSymbols', False):
                    findings.append({
                        'service': 'IAM',
                        'resource': 'Account',
                        'severity': 'MEDIUM',
                        'issue': 'Política de contraseñas no requiere símbolos',
                        'recommendation': 'Requerir símbolos en contraseñas'
                    })

                if not pwd_policy.get('ExpirePasswords', False):
                    findings.append({
                        'service': 'IAM',
                        'resource': 'Account',
                        'severity': 'HIGH',
                        'issue': 'Contraseñas no expiran',
                        'recommendation': 'Habilitar expiración de contraseñas (90 días)'
                    })

            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append({
                        'service': 'IAM',
                        'resource': 'Account',
                        'severity': 'CRITICAL',
                        'issue': 'No hay política de contraseñas configurada',
                        'recommendation': 'Configurar política de contraseñas robusta'
                    })

            # 2. Verificar usuarios
            users = self.iam.list_users()

            for user in users.get('Users', []):
                username = user['UserName']

                # Verificar MFA
                mfa_devices = self.iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get('MFADevices'):
                    findings.append({
                        'service': 'IAM',
                        'resource': username,
                        'severity': 'HIGH',
                        'issue': 'Usuario sin MFA habilitado',
                        'recommendation': 'Habilitar MFA para el usuario'
                    })

                # Verificar claves de acceso antiguas
                access_keys = self.iam.list_access_keys(UserName=username)
                for key in access_keys.get('AccessKeyMetadata', []):
                    create_date = key['CreateDate']
                    age = (datetime.now(timezone.utc) - create_date).days

                    if age > 90:
                        findings.append({
                            'service': 'IAM',
                            'resource': username,
                            'severity': 'HIGH',
                            'issue': f'Clave de acceso con {age} días de antigüedad',
                            'recommendation': 'Rotar claves de acceso cada 90 días'
                        })

                # Verificar políticas administradas peligrosas
                attached_policies = self.iam.list_attached_user_policies(UserName=username)
                for policy in attached_policies.get('AttachedPolicies', []):
                    policy_name = policy['PolicyName']
                    if 'Admin' in policy_name or 'FullAccess' in policy_name:
                        findings.append({
                            'service': 'IAM',
                            'resource': username,
                            'severity': 'HIGH',
                            'issue': f'Usuario con política amplia: {policy_name}',
                            'recommendation': 'Aplicar principio de mínimo privilegio'
                        })

        except Exception as e:
            print(f"[!] Error escaneando IAM: {str(e)}")

        return findings

    def scan_ec2_security(self):
        """
        Escanea seguridad de EC2
        """
        print("\n[*] Escaneando instancias EC2 y Security Groups...")
        findings = []

        try:
            # 1. Verificar Security Groups
            security_groups = self.ec2.describe_security_groups()

            CRITICAL_PORTS = {
                22: 'SSH',
                3389: 'RDP',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                1433: 'MS SQL Server',
                27017: 'MongoDB',
                6379: 'Redis',
                9200: 'Elasticsearch'
            }

            for sg in security_groups.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'N/A')

                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 'All')
                    to_port = rule.get('ToPort', 'All')

                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')

                        if cidr == '0.0.0.0/0':
                            if from_port == 'All':
                                severity = 'CRITICAL'
                                issue = 'Todos los puertos abiertos a Internet'
                            elif from_port in CRITICAL_PORTS:
                                severity = 'CRITICAL'
                                service = CRITICAL_PORTS[from_port]
                                issue = f'{service} (puerto {from_port}) expuesto a Internet'
                            else:
                                severity = 'HIGH'
                                issue = f'Puerto {from_port} expuesto a Internet'

                            findings.append({
                                'service': 'EC2',
                                'resource': f'{sg_name} ({sg_id})',
                                'severity': severity,
                                'issue': issue,
                                'recommendation': 'Restringir acceso a IPs específicas'
                            })

            # 2. Verificar instancias
            instances = self.ec2.describe_instances()

            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']

                    if state == 'running':
                        # Verificar si tiene IP pública
                        public_ip = instance.get('PublicIpAddress')
                        if public_ip:
                            # Verificar IMDSv2
                            metadata_options = instance.get('MetadataOptions', {})
                            if metadata_options.get('HttpTokens') != 'required':
                                findings.append({
                                    'service': 'EC2',
                                    'resource': instance_id,
                                    'severity': 'MEDIUM',
                                    'issue': 'IMDSv2 no requerido',
                                    'recommendation': 'Habilitar IMDSv2 obligatorio'
                                })

                        # Verificar cifrado de volúmenes
                        for bdm in instance.get('BlockDeviceMappings', []):
                            ebs = bdm.get('Ebs', {})
                            volume_id = ebs.get('VolumeId')

                            if volume_id:
                                volume = self.ec2.describe_volumes(VolumeIds=[volume_id])
                                encrypted = volume['Volumes'][0].get('Encrypted', False)

                                if not encrypted:
                                    findings.append({
                                        'service': 'EC2',
                                        'resource': f'{instance_id}/{volume_id}',
                                        'severity': 'HIGH',
                                        'issue': 'Volumen EBS no cifrado',
                                        'recommendation': 'Habilitar cifrado de volúmenes EBS'
                                    })

        except Exception as e:
            print(f"[!] Error escaneando EC2: {str(e)}")

        return findings

    def scan_rds_security(self):
        """
        Escanea seguridad de RDS
        """
        print("\n[*] Escaneando instancias RDS...")
        findings = []

        try:
            instances = self.rds.describe_db_instances()

            for instance in instances.get('DBInstances', []):
                db_id = instance['DBInstanceIdentifier']

                # 1. Verificar accesibilidad pública
                if instance.get('PubliclyAccessible', False):
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'CRITICAL',
                        'issue': 'Base de datos accesible públicamente',
                        'recommendation': 'Deshabilitar acceso público'
                    })

                # 2. Verificar cifrado
                if not instance.get('StorageEncrypted', False):
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'HIGH',
                        'issue': 'Almacenamiento no cifrado',
                        'recommendation': 'Habilitar cifrado de almacenamiento'
                    })

                # 3. Verificar backups automáticos
                if instance.get('BackupRetentionPeriod', 0) == 0:
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'HIGH',
                        'issue': 'Backups automáticos deshabilitados',
                        'recommendation': 'Habilitar backups con retención de al menos 7 días'
                    })

                # 4. Verificar multi-AZ
                if not instance.get('MultiAZ', False):
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'MEDIUM',
                        'issue': 'Multi-AZ no habilitado',
                        'recommendation': 'Habilitar Multi-AZ para alta disponibilidad'
                    })

        except Exception as e:
            print(f"[!] Error escaneando RDS: {str(e)}")

        return findings

    def scan_lambda_security(self):
        """
        Escanea seguridad de funciones Lambda
        """
        print("\n[*] Escaneando funciones Lambda...")
        findings = []

        try:
            functions = self.lambda_client.list_functions()

            for function in functions.get('Functions', []):
                func_name = function['FunctionName']

                # 1. Verificar variables de entorno
                env_vars = function.get('Environment', {}).get('Variables', {})
                sensitive_keywords = ['password', 'secret', 'key', 'token', 'api']

                for key, value in env_vars.items():
                    for keyword in sensitive_keywords:
                        if keyword.lower() in key.lower():
                            findings.append({
                                'service': 'Lambda',
                                'resource': func_name,
                                'severity': 'HIGH',
                                'issue': f'Variable de entorno sensible detectada: {key}',
                                'recommendation': 'Usar AWS Secrets Manager o Parameter Store'
                            })

                # 2. Verificar permisos del rol
                role_arn = function.get('Role', '')
                if role_arn:
                    role_name = role_arn.split('/')[-1]

                    try:
                        attached_policies = self.iam.list_attached_role_policies(RoleName=role_name)
                        for policy in attached_policies.get('AttachedPolicies', []):
                            if 'FullAccess' in policy['PolicyName']:
                                findings.append({
                                    'service': 'Lambda',
                                    'resource': func_name,
                                    'severity': 'HIGH',
                                    'issue': f'Rol con política amplia: {policy["PolicyName"]}',
                                    'recommendation': 'Aplicar principio de mínimo privilegio'
                                })
                    except:
                        pass

                # 3. Verificar VPC
                vpc_config = function.get('VpcConfig', {})
                if not vpc_config.get('VpcId'):
                    findings.append({
                        'service': 'Lambda',
                        'resource': func_name,
                        'severity': 'MEDIUM',
                        'issue': 'Función Lambda no está en VPC',
                        'recommendation': 'Considerar ejecutar en VPC si accede a recursos privados'
                    })

        except Exception as e:
            print(f"[!] Error escaneando Lambda: {str(e)}")

        return findings

    def scan_cloudtrail(self):
        """
        Verifica configuración de CloudTrail
        """
        print("\n[*] Verificando CloudTrail...")
        findings = []

        try:
            trails = self.cloudtrail.describe_trails()

            if not trails.get('trailList'):
                findings.append({
                    'service': 'CloudTrail',
                    'resource': 'Account',
                    'severity': 'CRITICAL',
                    'issue': 'CloudTrail no configurado',
                    'recommendation': 'Habilitar CloudTrail para auditoría'
                })
            else:
                for trail in trails['trailList']:
                    trail_name = trail['Name']

                    # Verificar si está habilitado
                    status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                    if not status.get('IsLogging', False):
                        findings.append({
                            'service': 'CloudTrail',
                            'resource': trail_name,
                            'severity': 'HIGH',
                            'issue': 'Trail no está logging',
                            'recommendation': 'Habilitar logging del trail'
                        })

                    # Verificar multi-region
                    if not trail.get('IsMultiRegionTrail', False):
                        findings.append({
                            'service': 'CloudTrail',
                            'resource': trail_name,
                            'severity': 'MEDIUM',
                            'issue': 'Trail no es multi-región',
                            'recommendation': 'Configurar como multi-región'
                        })

        except Exception as e:
            print(f"[!] Error verificando CloudTrail: {str(e)}")

        return findings

    def generate_report(self, all_findings):
        """
        Genera reporte completo de hallazgos
        """
        print("\n" + "=" * 70)
        print("REPORTE DE SEGURIDAD CLOUD")
        print("=" * 70)

        # Agrupar por severidad
        by_severity = defaultdict(list)
        for finding in all_findings:
            by_severity[finding['severity']].append(finding)

        # Estadísticas
        print(f"\n[+] Total de hallazgos: {len(all_findings)}")
        print(f"    CRÍTICO: {len(by_severity['CRITICAL'])}")
        print(f"    ALTO: {len(by_severity['HIGH'])}")
        print(f"    MEDIO: {len(by_severity['MEDIUM'])}")
        print(f"    BAJO: {len(by_severity['LOW'])}")

        # Detalles por severidad
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            findings = by_severity[severity]
            if findings:
                print(f"\n{'-' * 70}")
                print(f"HALLAZGOS DE SEVERIDAD {severity}:")
                print(f"{'-' * 70}")

                for finding in findings:
                    print(f"\n[{severity}] {finding['service']}: {finding['resource']}")
                    print(f"  Problema: {finding['issue']}")
                    print(f"  Recomendación: {finding['recommendation']}")

        # Score de seguridad
        total_score = 100
        total_score -= len(by_severity['CRITICAL']) * 10
        total_score -= len(by_severity['HIGH']) * 5
        total_score -= len(by_severity['MEDIUM']) * 2
        total_score -= len(by_severity['LOW']) * 1
        total_score = max(0, total_score)

        print(f"\n{'=' * 70}")
        print(f"PUNTUACIÓN DE SEGURIDAD: {total_score}/100")
        print(f"{'=' * 70}")

        if total_score >= 90:
            print("[+] Excelente - Postura de seguridad muy buena")
        elif total_score >= 70:
            print("[!] Bueno - Hay algunas áreas de mejora")
        elif total_score >= 50:
            print("[!] Regular - Se requieren mejoras significativas")
        else:
            print("[!] CRÍTICO - Se requiere acción inmediata")

        return total_score

    def export_json(self, findings, filename='security_scan_results.json'):
        """
        Exporta resultados a JSON
        """
        output = {
            'scan_date': datetime.now().isoformat(),
            'account_id': self.account_id,
            'region': self.region,
            'total_findings': len(findings),
            'findings': findings
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\n[+] Resultados exportados a: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Scanner comprehensivo de seguridad cloud para AWS'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='Región de AWS (default: us-east-1)'
    )
    parser.add_argument(
        '--profile',
        help='Perfil de AWS CLI'
    )
    parser.add_argument(
        '--services',
        nargs='+',
        choices=['s3', 'iam', 'ec2', 'rds', 'lambda', 'cloudtrail', 'all'],
        default=['all'],
        help='Servicios a escanear'
    )
    parser.add_argument(
        '--output',
        default='security_scan_results.json',
        help='Archivo de salida JSON'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("SCANNER DE SEGURIDAD CLOUD - CLASE 7")
    print("UTN - Laboratorio de Ciberseguridad")
    print("=" * 70)

    # Inicializar scanner
    scanner = CloudSecurityScanner(region=args.region, profile=args.profile)

    # Ejecutar scans
    all_findings = []

    services = args.services
    if 'all' in services:
        services = ['s3', 'iam', 'ec2', 'rds', 'lambda', 'cloudtrail']

    if 's3' in services:
        all_findings.extend(scanner.scan_s3_security())

    if 'iam' in services:
        all_findings.extend(scanner.scan_iam_security())

    if 'ec2' in services:
        all_findings.extend(scanner.scan_ec2_security())

    if 'rds' in services:
        all_findings.extend(scanner.scan_rds_security())

    if 'lambda' in services:
        all_findings.extend(scanner.scan_lambda_security())

    if 'cloudtrail' in services:
        all_findings.extend(scanner.scan_cloudtrail())

    # Generar reporte
    score = scanner.generate_report(all_findings)

    # Exportar resultados
    scanner.export_json(all_findings, args.output)

    # Retornar código de salida basado en hallazgos críticos
    critical_count = len([f for f in all_findings if f['severity'] == 'CRITICAL'])
    if critical_count > 0:
        print(f"\n[!] ATENCIÓN: {critical_count} hallazgos CRÍTICOS requieren acción inmediata")
        sys.exit(1)
    else:
        print("\n[+] Scan completado")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrumpido por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] ERROR FATAL: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
