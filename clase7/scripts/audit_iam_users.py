#!/usr/bin/env python3
"""
CLASE 7 - SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN
Script Adicional: Auditoría de Usuarios IAM

Descripción:
Este script audita usuarios IAM en AWS para identificar
configuraciones inseguras y permisos excesivos.

Autor: UTN - Laboratorio de Ciberseguridad
Versión: 1.0
"""

import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone
import json


class IAMAuditor:
    """
    Auditor de usuarios y políticas IAM.
    Identifica configuraciones inseguras y violaciones de mejores prácticas.
    """

    def __init__(self, profile_name=None):
        """
        Inicializa el auditor con credenciales de AWS.

        Args:
            profile_name (str): Nombre del perfil de AWS CLI (opcional)
        """
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                self.iam = session.client('iam')
            else:
                self.iam = boto3.client('iam')

            print("[+] Conexión establecida con AWS IAM")
            print(f"[+] Fecha de auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 70)

        except NoCredentialsError:
            print("[!] ERROR: No se encontraron credenciales de AWS")
            print("[!] Configure sus credenciales con 'aws configure'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] ERROR al conectar con AWS: {str(e)}")
            sys.exit(1)

    def list_users(self):
        """
        Lista todos los usuarios IAM.

        Returns:
            list: Lista de usuarios IAM
        """
        try:
            paginator = self.iam.get_paginator('list_users')
            users = []

            for response in paginator.paginate():
                users.extend(response.get('Users', []))

            print(f"[+] Se encontraron {len(users)} usuarios IAM")
            return users

        except ClientError as e:
            print(f"[!] ERROR al listar usuarios: {e}")
            return []

    def check_mfa_status(self, username):
        """
        Verifica si un usuario tiene MFA habilitado.

        Args:
            username (str): Nombre del usuario

        Returns:
            dict: Estado de MFA del usuario
        """
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            mfa_devices = response.get('MFADevices', [])

            return {
                'has_mfa': len(mfa_devices) > 0,
                'device_count': len(mfa_devices)
            }

        except ClientError as e:
            return {
                'has_mfa': False,
                'device_count': 0,
                'error': str(e)
            }

    def check_access_keys(self, username):
        """
        Verifica las claves de acceso del usuario.

        Args:
            username (str): Nombre del usuario

        Returns:
            list: Lista de hallazgos sobre claves de acceso
        """
        findings = []

        try:
            response = self.iam.list_access_keys(UserName=username)
            access_keys = response.get('AccessKeyMetadata', [])

            for key in access_keys:
                key_id = key['AccessKeyId']
                status = key['Status']
                create_date = key['CreateDate']

                # Calcular antigüedad de la clave
                age = (datetime.now(timezone.utc) - create_date).days

                # Verificar si la clave es antigua (más de 90 días)
                if age > 90:
                    findings.append({
                        'type': 'OLD_ACCESS_KEY',
                        'severity': 'ALTO',
                        'key_id': key_id,
                        'age_days': age,
                        'status': status,
                        'message': f'Clave de acceso con {age} días de antigüedad'
                    })

                # Verificar si hay múltiples claves activas
                if status == 'Active' and len([k for k in access_keys if k['Status'] == 'Active']) > 1:
                    findings.append({
                        'type': 'MULTIPLE_ACTIVE_KEYS',
                        'severity': 'MEDIO',
                        'key_id': key_id,
                        'message': 'Usuario tiene múltiples claves de acceso activas'
                    })

                # Obtener último uso de la clave
                try:
                    last_used = self.iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                    if last_used_date:
                        inactive_days = (datetime.now(timezone.utc) - last_used_date).days
                        if inactive_days > 90:
                            findings.append({
                                'type': 'UNUSED_ACCESS_KEY',
                                'severity': 'MEDIO',
                                'key_id': key_id,
                                'inactive_days': inactive_days,
                                'message': f'Clave no usada en {inactive_days} días'
                            })

                except ClientError:
                    pass

            return findings

        except ClientError as e:
            return []

    def check_password_policy(self):
        """
        Verifica la política de contraseñas de la cuenta.

        Returns:
            dict: Hallazgos sobre la política de contraseñas
        """
        try:
            policy = self.iam.get_account_password_policy()
            password_policy = policy.get('PasswordPolicy', {})

            findings = []

            # Verificar longitud mínima
            min_length = password_policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                findings.append({
                    'type': 'WEAK_PASSWORD_POLICY',
                    'severity': 'ALTO',
                    'field': 'MinimumPasswordLength',
                    'value': min_length,
                    'recommendation': 'Usar longitud mínima de 14 caracteres'
                })

            # Verificar complejidad
            if not password_policy.get('RequireSymbols', False):
                findings.append({
                    'type': 'WEAK_PASSWORD_POLICY',
                    'severity': 'MEDIO',
                    'field': 'RequireSymbols',
                    'value': False,
                    'recommendation': 'Requerir símbolos en contraseñas'
                })

            if not password_policy.get('RequireNumbers', False):
                findings.append({
                    'type': 'WEAK_PASSWORD_POLICY',
                    'severity': 'MEDIO',
                    'field': 'RequireNumbers',
                    'value': False,
                    'recommendation': 'Requerir números en contraseñas'
                })

            # Verificar rotación
            if not password_policy.get('ExpirePasswords', False):
                findings.append({
                    'type': 'WEAK_PASSWORD_POLICY',
                    'severity': 'ALTO',
                    'field': 'ExpirePasswords',
                    'value': False,
                    'recommendation': 'Habilitar expiración de contraseñas'
                })

            return {
                'has_policy': True,
                'policy': password_policy,
                'findings': findings
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchEntity':
                return {
                    'has_policy': False,
                    'findings': [{
                        'type': 'NO_PASSWORD_POLICY',
                        'severity': 'CRÍTICO',
                        'message': 'No hay política de contraseñas configurada'
                    }]
                }
            return {
                'has_policy': False,
                'error': str(e),
                'findings': []
            }

    def check_user_policies(self, username):
        """
        Verifica las políticas asociadas a un usuario.

        Args:
            username (str): Nombre del usuario

        Returns:
            dict: Información sobre políticas del usuario
        """
        findings = []

        try:
            # Políticas inline
            inline_policies = self.iam.list_user_policies(UserName=username)
            inline_count = len(inline_policies.get('PolicyNames', []))

            # Políticas administradas
            managed_policies = self.iam.list_attached_user_policies(UserName=username)
            managed_list = managed_policies.get('AttachedPolicies', [])

            # Verificar políticas administradas por AWS
            for policy in managed_list:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']

                # Verificar políticas peligrosas
                if 'AdministratorAccess' in policy_name:
                    findings.append({
                        'type': 'EXCESSIVE_PERMISSIONS',
                        'severity': 'CRÍTICO',
                        'policy': policy_name,
                        'message': 'Usuario tiene acceso de administrador completo'
                    })

                elif 'PowerUser' in policy_name:
                    findings.append({
                        'type': 'EXCESSIVE_PERMISSIONS',
                        'severity': 'ALTO',
                        'policy': policy_name,
                        'message': 'Usuario tiene permisos de PowerUser'
                    })

            return {
                'inline_policies': inline_count,
                'managed_policies': len(managed_list),
                'findings': findings
            }

        except ClientError as e:
            return {
                'inline_policies': 0,
                'managed_policies': 0,
                'error': str(e),
                'findings': []
            }

    def audit_user(self, user):
        """
        Audita un usuario individual.

        Args:
            user (dict): Información del usuario

        Returns:
            dict: Resultados de la auditoría del usuario
        """
        username = user['UserName']
        create_date = user['CreateDate']

        # MFA
        mfa_status = self.check_mfa_status(username)

        # Claves de acceso
        access_key_findings = self.check_access_keys(username)

        # Políticas
        policy_info = self.check_user_policies(username)

        # Consolidar hallazgos
        all_findings = []

        if not mfa_status['has_mfa']:
            all_findings.append({
                'type': 'NO_MFA',
                'severity': 'CRÍTICO',
                'message': 'Usuario no tiene MFA habilitado'
            })

        all_findings.extend(access_key_findings)
        all_findings.extend(policy_info['findings'])

        return {
            'username': username,
            'create_date': create_date.isoformat(),
            'mfa_enabled': mfa_status['has_mfa'],
            'findings': all_findings
        }

    def audit_all_users(self):
        """
        Audita todos los usuarios IAM.

        Returns:
            dict: Resultados de la auditoría
        """
        print("\n[*] Iniciando auditoría de usuarios IAM...")
        print("-" * 70)

        users = self.list_users()
        user_results = []

        for user in users:
            result = self.audit_user(user)
            user_results.append(result)

        # Verificar política de contraseñas
        password_policy_info = self.check_password_policy()

        return {
            'timestamp': datetime.now().isoformat(),
            'total_users': len(users),
            'password_policy': password_policy_info,
            'users': user_results
        }

    def print_report(self, results):
        """
        Imprime un reporte de los hallazgos.

        Args:
            results (dict): Resultados de la auditoría
        """
        print("\n" + "=" * 70)
        print("REPORTE DE AUDITORÍA IAM")
        print("=" * 70)

        print(f"\n[+] Total de usuarios: {results['total_users']}")

        # Resumen de hallazgos
        all_findings = []
        for user in results['users']:
            all_findings.extend(user['findings'])

        # Agregar hallazgos de política de contraseñas
        all_findings.extend(results['password_policy'].get('findings', []))

        critical = [f for f in all_findings if f['severity'] == 'CRÍTICO']
        high = [f for f in all_findings if f['severity'] == 'ALTO']
        medium = [f for f in all_findings if f['severity'] == 'MEDIO']

        print(f"[!] Total de hallazgos: {len(all_findings)}")
        print(f"    CRÍTICO: {len(critical)}")
        print(f"    ALTO: {len(high)}")
        print(f"    MEDIO: {len(medium)}")

        # Política de contraseñas
        print("\n" + "-" * 70)
        print("POLÍTICA DE CONTRASEÑAS:")
        print("-" * 70)

        if results['password_policy']['has_policy']:
            print("[+] Política de contraseñas configurada")
            policy_findings = results['password_policy'].get('findings', [])
            if policy_findings:
                for finding in policy_findings:
                    print(f"[{finding['severity']}] {finding.get('field', 'Policy')}: {finding.get('recommendation', finding.get('message'))}")
        else:
            print("[!] CRÍTICO: No hay política de contraseñas configurada")

        # Usuarios con problemas
        print("\n" + "-" * 70)
        print("USUARIOS CON HALLAZGOS:")
        print("-" * 70)

        for user_result in results['users']:
            if user_result['findings']:
                print(f"\n[!] Usuario: {user_result['username']}")
                print(f"    MFA: {'✓' if user_result['mfa_enabled'] else '✗ NO HABILITADO'}")
                print(f"    Hallazgos:")

                for finding in user_result['findings']:
                    print(f"      [{finding['severity']}] {finding['message']}")

        print("\n" + "=" * 70)
        print("RECOMENDACIONES:")
        print("=" * 70)
        print("""
1. Habilitar MFA para TODOS los usuarios, especialmente con privilegios
2. Rotar claves de acceso cada 90 días
3. Eliminar claves de acceso no utilizadas
4. Implementar política de contraseñas robusta (mínimo 14 caracteres)
5. Usar roles de IAM en lugar de usuarios para servicios
6. Aplicar principio de mínimo privilegio
7. Revisar y auditar permisos regularmente
8. Usar AWS Organizations para control centralizado
9. Implementar AWS IAM Access Analyzer
10. Monitorear actividad con CloudTrail
        """)

    def export_to_json(self, results, filename='iam_audit_results.json'):
        """
        Exporta los resultados a un archivo JSON.

        Args:
            results (dict): Resultados de la auditoría
            filename (str): Nombre del archivo de salida
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            print(f"\n[+] Resultados exportados a: {filename}")

        except Exception as e:
            print(f"[!] ERROR al exportar resultados: {e}")


def main():
    """
    Función principal del script.
    """
    print("=" * 70)
    print("AUDITOR IAM - CLASE 7")
    print("UTN - Laboratorio de Ciberseguridad")
    print("=" * 70)

    # Inicializar auditor
    auditor = IAMAuditor()

    # Ejecutar auditoría
    results = auditor.audit_all_users()

    # Mostrar reporte
    auditor.print_report(results)

    # Exportar resultados
    auditor.export_to_json(results)

    # Retornar código de salida
    all_findings = []
    for user in results['users']:
        all_findings.extend(user['findings'])
    all_findings.extend(results['password_policy'].get('findings', []))

    critical_findings = [f for f in all_findings if f['severity'] == 'CRÍTICO']

    if critical_findings:
        print(f"\n[!] ATENCIÓN: Se encontraron {len(critical_findings)} hallazgos CRÍTICOS")
        sys.exit(1)
    else:
        print("\n[+] No se encontraron hallazgos críticos")
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
