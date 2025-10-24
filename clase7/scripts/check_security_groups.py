#!/usr/bin/env python3
"""
CLASE 7 - SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN
Script Adicional: Auditoría de Security Groups

Descripción:
Este script audita Security Groups de EC2 en AWS para identificar
reglas que permitan acceso público inseguro.

Autor: UTN FRVM - Laboratorio de Ciberseguridad
Versión: 1.0
"""

import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime
import json


class SecurityGroupAuditor:
    """
    Auditor de Security Groups para EC2.
    Identifica reglas inseguras que permiten acceso público no autorizado.
    """

    # Puertos considerados críticos
    CRITICAL_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        1433: 'MS SQL Server',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        5984: 'CouchDB',
        9200: 'Elasticsearch',
        8080: 'HTTP Alternative',
        8443: 'HTTPS Alternative'
    }

    def __init__(self, region='us-east-1', profile_name=None):
        """
        Inicializa el auditor con credenciales de AWS.

        Args:
            region (str): Región de AWS
            profile_name (str): Nombre del perfil de AWS CLI (opcional)
        """
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name, region_name=region)
                self.ec2 = session.client('ec2')
            else:
                self.ec2 = boto3.client('ec2', region_name=region)

            self.region = region
            print(f"[+] Conexión establecida con AWS EC2 (Región: {region})")
            print(f"[+] Fecha de auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 70)

        except NoCredentialsError:
            print("[!] ERROR: No se encontraron credenciales de AWS")
            print("[!] Configure sus credenciales con 'aws configure'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] ERROR al conectar con AWS: {str(e)}")
            sys.exit(1)

    def list_security_groups(self):
        """
        Lista todos los Security Groups de la región.

        Returns:
            list: Lista de Security Groups
        """
        try:
            response = self.ec2.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            print(f"[+] Se encontraron {len(security_groups)} Security Groups")
            return security_groups
        except ClientError as e:
            print(f"[!] ERROR al listar Security Groups: {e}")
            return []

    def analyze_ingress_rules(self, sg):
        """
        Analiza las reglas de entrada de un Security Group.

        Args:
            sg (dict): Información del Security Group

        Returns:
            list: Lista de hallazgos de seguridad
        """
        findings = []
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 'All')
            to_port = rule.get('ToPort', 'All')
            protocol = rule.get('IpProtocol', 'All')

            # Analizar rangos de IP
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')

                # Verificar acceso público (0.0.0.0/0)
                if cidr == '0.0.0.0/0':
                    severity = self._determine_severity(from_port, to_port)

                    finding = {
                        'sg_id': sg_id,
                        'sg_name': sg_name,
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'cidr': cidr,
                        'severity': severity,
                        'description': ip_range.get('Description', 'Sin descripción')
                    }
                    findings.append(finding)

            # Analizar rangos de IPv6
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr_ipv6 = ipv6_range.get('CidrIpv6', '')

                # Verificar acceso público IPv6 (::/0)
                if cidr_ipv6 == '::/0':
                    severity = self._determine_severity(from_port, to_port)

                    finding = {
                        'sg_id': sg_id,
                        'sg_name': sg_name,
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'cidr': cidr_ipv6,
                        'severity': severity,
                        'description': ipv6_range.get('Description', 'Sin descripción')
                    }
                    findings.append(finding)

        return findings

    def _determine_severity(self, from_port, to_port):
        """
        Determina la severidad basándose en los puertos expuestos.

        Args:
            from_port: Puerto inicial
            to_port: Puerto final

        Returns:
            str: Nivel de severidad
        """
        # Si todos los puertos están abiertos
        if from_port == 'All' or to_port == 'All':
            return 'CRÍTICO'

        # Verificar si hay puertos críticos en el rango
        for port in range(int(from_port), int(to_port) + 1):
            if port in self.CRITICAL_PORTS:
                return 'CRÍTICO'

        # Puertos menores a 1024 (well-known ports)
        if int(from_port) < 1024:
            return 'ALTO'

        return 'MEDIO'

    def audit_security_groups(self):
        """
        Audita todos los Security Groups.

        Returns:
            dict: Resultados de la auditoría
        """
        print("\n[*] Iniciando auditoría de Security Groups...")
        print("-" * 70)

        security_groups = self.list_security_groups()
        all_findings = []

        for sg in security_groups:
            findings = self.analyze_ingress_rules(sg)
            all_findings.extend(findings)

        return {
            'region': self.region,
            'timestamp': datetime.now().isoformat(),
            'total_security_groups': len(security_groups),
            'findings': all_findings
        }

    def print_report(self, results):
        """
        Imprime un reporte de los hallazgos.

        Args:
            results (dict): Resultados de la auditoría
        """
        findings = results['findings']

        print("\n" + "=" * 70)
        print("REPORTE DE AUDITORÍA DE SECURITY GROUPS")
        print("=" * 70)

        print(f"\n[+] Región: {results['region']}")
        print(f"[+] Security Groups analizados: {results['total_security_groups']}")
        print(f"[!] Hallazgos de seguridad: {len(findings)}")

        if findings:
            # Agrupar por severidad
            critical = [f for f in findings if f['severity'] == 'CRÍTICO']
            high = [f for f in findings if f['severity'] == 'ALTO']
            medium = [f for f in findings if f['severity'] == 'MEDIO']

            print(f"\n    CRÍTICO: {len(critical)}")
            print(f"    ALTO: {len(high)}")
            print(f"    MEDIO: {len(medium)}")

            print("\n" + "-" * 70)
            print("HALLAZGOS DETALLADOS:")
            print("-" * 70)

            for finding in findings:
                print(f"\n[{finding['severity']}] Security Group: {finding['sg_name']} ({finding['sg_id']})")
                print(f"    Protocolo: {finding['protocol']}")

                if finding['from_port'] == 'All':
                    print(f"    Puerto: TODOS")
                elif finding['from_port'] == finding['to_port']:
                    port = finding['from_port']
                    service = self.CRITICAL_PORTS.get(port, 'Desconocido')
                    print(f"    Puerto: {port} ({service})")
                else:
                    print(f"    Puertos: {finding['from_port']}-{finding['to_port']}")

                print(f"    Origen: {finding['cidr']}")
                print(f"    Descripción: {finding['description']}")

                # Recomendación
                if finding['severity'] == 'CRÍTICO':
                    print("    [!] ACCIÓN INMEDIATA: Restringir acceso a IPs específicas")

        print("\n" + "=" * 70)
        print("RECOMENDACIONES:")
        print("=" * 70)
        print("""
1. Nunca usar 0.0.0.0/0 para puertos críticos (SSH, RDP, bases de datos)
2. Implementar bastion hosts para acceso administrativo
3. Usar Security Groups con principio de mínimo privilegio
4. Habilitar VPC Flow Logs para monitoreo de tráfico
5. Usar AWS Systems Manager Session Manager en lugar de SSH directo
6. Implementar Network ACLs como segunda capa de defensa
7. Revisar y auditar Security Groups regularmente
8. Usar AWS Config Rules para compliance automático
        """)

    def export_to_json(self, results, filename='sg_audit_results.json'):
        """
        Exporta los resultados a un archivo JSON.

        Args:
            results (dict): Resultados de la auditoría
            filename (str): Nombre del archivo de salida
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)

            print(f"\n[+] Resultados exportados a: {filename}")

        except Exception as e:
            print(f"[!] ERROR al exportar resultados: {e}")


def main():
    """
    Función principal del script.
    """
    print("=" * 70)
    print("AUDITOR DE SECURITY GROUPS - CLASE 7")
    print("UTN - Laboratorio de Ciberseguridad")
    print("=" * 70)

    # Permitir especificar región como argumento
    region = sys.argv[1] if len(sys.argv) > 1 else 'us-east-1'

    # Inicializar auditor
    auditor = SecurityGroupAuditor(region=region)

    # Ejecutar auditoría
    results = auditor.audit_security_groups()

    # Mostrar reporte
    auditor.print_report(results)

    # Exportar resultados
    auditor.export_to_json(results)

    # Retornar código de salida
    critical_findings = [f for f in results['findings'] if f['severity'] == 'CRÍTICO']
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
