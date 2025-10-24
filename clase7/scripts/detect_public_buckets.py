#!/usr/bin/env python3
"""
CLASE 7 - SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN
Ejercicio 1: Detección de Buckets S3 Públicos

Descripción:
Este script audita buckets de S3 en AWS para identificar configuraciones
inseguras que permitan acceso público no autorizado.

Autor: UTN FRVM - Laboratorio de Ciberseguridad
Versión: 1.0
"""

import boto3
import sys
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from datetime import datetime
import json


class S3SecurityAuditor:
    """
    Auditor de seguridad para buckets S3 de AWS.
    Identifica configuraciones inseguras y genera reportes.
    """

    def __init__(self, profile_name=None, region=None):
        """
        Inicializa el auditor con credenciales de AWS.

        Args:
            profile_name (str): Nombre del perfil de AWS CLI (opcional)
            region (str): Región de AWS (opcional)
        """
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                self.s3 = session.client('s3')
            else:
                self.s3 = boto3.client('s3', region_name=region)

            print("[+] Conexión establecida con AWS S3")
            print(f"[+] Fecha de auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 70)

        except NoCredentialsError:
            print("[!] ERROR: No se encontraron credenciales de AWS")
            print("[!] Configure sus credenciales con 'aws configure'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] ERROR al conectar con AWS: {str(e)}")
            sys.exit(1)

    def list_all_buckets(self):
        """
        Lista todos los buckets S3 de la cuenta.

        Returns:
            list: Lista de nombres de buckets
        """
        try:
            response = self.s3.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            print(f"[+] Se encontraron {len(buckets)} buckets en la cuenta")
            return buckets
        except ClientError as e:
            print(f"[!] ERROR al listar buckets: {e}")
            return []

    def check_bucket_acl(self, bucket_name):
        """
        Verifica la ACL de un bucket específico.

        Args:
            bucket_name (str): Nombre del bucket

        Returns:
            dict: Información sobre permisos públicos encontrados
        """
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            public_permissions = []

            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')

                # Verificar acceso público
                uri = grantee.get('URI', '')
                if uri in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    group_type = "AllUsers" if "AllUsers" in uri else "AuthenticatedUsers"
                    public_permissions.append({
                        'group': group_type,
                        'permission': permission
                    })

            return {
                'bucket': bucket_name,
                'is_public': len(public_permissions) > 0,
                'permissions': public_permissions
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                return {
                    'bucket': bucket_name,
                    'is_public': False,
                    'error': 'AccessDenied',
                    'permissions': []
                }
            else:
                print(f"[!] ERROR al verificar ACL de {bucket_name}: {e}")
                return {
                    'bucket': bucket_name,
                    'is_public': False,
                    'error': str(e),
                    'permissions': []
                }

    def check_bucket_policy(self, bucket_name):
        """
        Verifica la política del bucket para acceso público.

        Args:
            bucket_name (str): Nombre del bucket

        Returns:
            dict: Información sobre la política del bucket
        """
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(policy['Policy'])

            # Analizar si la política permite acceso público
            has_public_policy = False
            public_statements = []

            for statement in policy_document.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')

                # Verificar si el principal es público
                if (principal == '*' or
                    principal.get('AWS') == '*' or
                    principal == {"AWS": "*"}):
                    if effect == 'Allow':
                        has_public_policy = True
                        public_statements.append({
                            'effect': effect,
                            'actions': statement.get('Action', []),
                            'resources': statement.get('Resource', [])
                        })

            return {
                'has_policy': True,
                'is_public': has_public_policy,
                'statements': public_statements
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchBucketPolicy':
                return {
                    'has_policy': False,
                    'is_public': False,
                    'statements': []
                }
            else:
                return {
                    'has_policy': False,
                    'is_public': False,
                    'error': str(e),
                    'statements': []
                }

    def check_public_access_block(self, bucket_name):
        """
        Verifica la configuración de bloqueo de acceso público.

        Args:
            bucket_name (str): Nombre del bucket

        Returns:
            dict: Configuración del bloqueo de acceso público
        """
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})

            return {
                'enabled': True,
                'block_public_acls': config.get('BlockPublicAcls', False),
                'ignore_public_acls': config.get('IgnorePublicAcls', False),
                'block_public_policy': config.get('BlockPublicPolicy', False),
                'restrict_public_buckets': config.get('RestrictPublicBuckets', False)
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                return {
                    'enabled': False,
                    'block_public_acls': False,
                    'ignore_public_acls': False,
                    'block_public_policy': False,
                    'restrict_public_buckets': False
                }
            else:
                return {
                    'enabled': False,
                    'error': str(e)
                }

    def audit_bucket(self, bucket_name, verbose=False):
        """
        Realiza auditoría completa de un bucket.

        Args:
            bucket_name (str): Nombre del bucket
            verbose (bool): Mostrar información detallada

        Returns:
            dict: Resultados de la auditoría
        """
        if verbose:
            print(f"\n[*] Auditando: {bucket_name}")

        # Verificar ACL
        acl_info = self.check_bucket_acl(bucket_name)

        # Verificar política
        policy_info = self.check_bucket_policy(bucket_name)

        # Verificar bloqueo de acceso público
        block_info = self.check_public_access_block(bucket_name)

        # Determinar si el bucket es público
        is_public = (acl_info['is_public'] or policy_info['is_public'])

        # Determinar nivel de riesgo
        if is_public and not block_info['enabled']:
            risk_level = "CRÍTICO"
        elif is_public and block_info['enabled']:
            risk_level = "ALTO"
        elif not block_info['enabled']:
            risk_level = "MEDIO"
        else:
            risk_level = "BAJO"

        result = {
            'bucket': bucket_name,
            'is_public': is_public,
            'risk_level': risk_level,
            'acl': acl_info,
            'policy': policy_info,
            'public_access_block': block_info
        }

        return result

    def audit_all_buckets(self, verbose=False):
        """
        Audita todos los buckets de la cuenta.

        Args:
            verbose (bool): Mostrar información detallada

        Returns:
            list: Lista de resultados de auditoría
        """
        buckets = self.list_all_buckets()

        if not buckets:
            print("[!] No se encontraron buckets para auditar")
            return []

        print("\n[*] Iniciando auditoría de seguridad...")
        print("-" * 70)

        results = []
        for bucket_name in buckets:
            result = self.audit_bucket(bucket_name, verbose)
            results.append(result)

        return results

    def print_summary(self, results):
        """
        Imprime un resumen de los resultados de la auditoría.

        Args:
            results (list): Lista de resultados de auditoría
        """
        print("\n" + "=" * 70)
        print("RESUMEN DE AUDITORÍA DE SEGURIDAD S3")
        print("=" * 70)

        total_buckets = len(results)
        public_buckets = [r for r in results if r['is_public']]
        critical_buckets = [r for r in results if r['risk_level'] == 'CRÍTICO']
        high_risk_buckets = [r for r in results if r['risk_level'] == 'ALTO']

        print(f"\n[+] Total de buckets analizados: {total_buckets}")
        print(f"[!] Buckets públicos encontrados: {len(public_buckets)}")
        print(f"[!] Buckets con riesgo CRÍTICO: {len(critical_buckets)}")
        print(f"[!] Buckets con riesgo ALTO: {len(high_risk_buckets)}")

        if public_buckets:
            print("\n" + "-" * 70)
            print("BUCKETS PÚBLICOS DETECTADOS:")
            print("-" * 70)

            for result in public_buckets:
                bucket_name = result['bucket']
                risk_level = result['risk_level']

                print(f"\n[!] Bucket: {bucket_name}")
                print(f"    Nivel de riesgo: {risk_level}")

                # Mostrar permisos de ACL
                if result['acl']['permissions']:
                    print("    Permisos ACL públicos:")
                    for perm in result['acl']['permissions']:
                        print(f"      - {perm['group']}: {perm['permission']}")

                # Mostrar política pública
                if result['policy']['is_public']:
                    print("    Política pública detectada:")
                    for stmt in result['policy']['statements']:
                        print(f"      - Actions: {stmt['actions']}")

                # Mostrar estado del bloqueo
                block_info = result['public_access_block']
                if not block_info['enabled']:
                    print("    [!] ADVERTENCIA: Bloqueo de acceso público NO configurado")

        print("\n" + "=" * 70)
        print("RECOMENDACIONES:")
        print("=" * 70)
        print("""
1. Revisar y eliminar permisos públicos innecesarios
2. Habilitar 'Block Public Access' en todos los buckets
3. Implementar políticas de bucket con principio de mínimo privilegio
4. Configurar cifrado en reposo (SSE-S3 o SSE-KMS)
5. Habilitar logging de acceso al bucket
6. Implementar versionado para protección contra eliminación
7. Usar AWS Config para monitoreo continuo
        """)

    def export_to_json(self, results, filename='audit_results.json'):
        """
        Exporta los resultados a un archivo JSON.

        Args:
            results (list): Lista de resultados de auditoría
            filename (str): Nombre del archivo de salida
        """
        try:
            output = {
                'timestamp': datetime.now().isoformat(),
                'total_buckets': len(results),
                'public_buckets': len([r for r in results if r['is_public']]),
                'results': results
            }

            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)

            print(f"\n[+] Resultados exportados a: {filename}")

        except Exception as e:
            print(f"[!] ERROR al exportar resultados: {e}")


def main():
    """
    Función principal del script.
    """
    print("=" * 70)
    print("AUDITOR DE SEGURIDAD S3 - CLASE 7")
    print("UTN - Laboratorio de Ciberseguridad")
    print("=" * 70)

    # Inicializar auditor
    auditor = S3SecurityAuditor()

    # Ejecutar auditoría
    results = auditor.audit_all_buckets(verbose=False)

    # Mostrar resumen
    auditor.print_summary(results)

    # Exportar resultados
    auditor.export_to_json(results)

    # Retornar código de salida
    public_count = len([r for r in results if r['is_public']])
    if public_count > 0:
        print(f"\n[!] ATENCIÓN: Se encontraron {public_count} buckets públicos")
        sys.exit(1)
    else:
        print("\n[+] No se encontraron buckets públicos")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Auditoría interrumpida por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] ERROR FATAL: {str(e)}")
        sys.exit(1)
