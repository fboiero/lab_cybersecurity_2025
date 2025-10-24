# CLASE 7 – SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN

## UTN | Laboratorio de Blockchain y Ciberseguridad

---

## CONTEXTO GENERAL DE LA MATERIA

### Laboratorio de Ciberseguridad
Este curso forma parte del programa de formación en ciberseguridad de la UTN, enfocado en competencias prácticas para la identificación, análisis y mitigación de vulnerabilidades en entornos reales y simulados.

**Áreas cubiertas en el programa:**
- Fundamentos de seguridad informática
- Análisis de vulnerabilidades y pentesting
- Seguridad en redes y sistemas
- Criptografía aplicada
- Seguridad en aplicaciones web
- Forense digital
- **Seguridad en la nube y virtualización** (Clase 7)
- Respuesta a incidentes
- Gestión de riesgos y compliance

---

## OBJETIVOS DE LA CLASE

Al finalizar esta clase, el estudiante será capaz de:

- ✅ Comprender los riesgos y desafíos de la seguridad en entornos cloud
- ✅ Aplicar controles y herramientas para proteger infraestructura virtualizada
- ✅ Identificar configuraciones inseguras y vulnerabilidades comunes
- ✅ Realizar auditorías básicas de entornos simulados de nube
- ✅ Implementar políticas de seguridad basadas en el principio de mínimo privilegio
- ✅ Analizar y remediar exposiciones de datos en servicios cloud

---

## PARTE TEÓRICA

### 📊 INTRODUCCIÓN

> **Estadística clave:**
> "El 94% de las empresas ya usa servicios cloud, pero solo el 40% tiene políticas de seguridad específicas."

**Conceptos fundamentales:**
- La nube no es insegura: lo inseguro es no entender quién es responsable
- Seguridad cloud ≠ seguridad tradicional
- La responsabilidad es compartida, pero no se terceriza

---

### 🏗️ MODELOS DE SERVICIO Y RESPONSABILIDAD

#### Infrastructure as a Service (IaaS)
**Usuario gestiona:**
- Sistema operativo
- Middleware
- Aplicaciones
- Datos

**Proveedor gestiona:**
- Hardware físico
- Red
- Virtualización

**Ejemplos:** AWS EC2, Azure VMs, Google Compute Engine

---

#### Platform as a Service (PaaS)
**Usuario gestiona:**
- Aplicaciones
- Datos

**Proveedor gestiona:**
- Runtime
- Middleware
- Sistema operativo
- Virtualización
- Hardware

**Ejemplos:** Heroku, Google App Engine, Azure App Service

---

#### Software as a Service (SaaS)
**Usuario gestiona:**
- Uso y configuración
- Gestión de usuarios

**Proveedor gestiona:**
- Infraestructura completa
- Aplicación
- Datos de la plataforma

**Ejemplos:** Gmail, Office 365, Salesforce

---

### 🔐 SHARED RESPONSIBILITY MODEL

| Componente | On-Premises | IaaS | PaaS | SaaS |
|------------|-------------|------|------|------|
| Datos | Cliente | Cliente | Cliente | Cliente |
| Aplicaciones | Cliente | Cliente | Cliente | Proveedor |
| Runtime | Cliente | Cliente | Proveedor | Proveedor |
| OS | Cliente | Cliente | Proveedor | Proveedor |
| Virtualización | Cliente | Proveedor | Proveedor | Proveedor |
| Hardware | Cliente | Proveedor | Proveedor | Proveedor |
| Red física | Cliente | Proveedor | Proveedor | Proveedor |

**Principio fundamental:**
> "La nube es compartida, la responsabilidad no se terceriza."

---

### ☁️ MODELOS DE DESPLIEGUE

#### Nube Pública
- Infraestructura compartida entre múltiples organizaciones
- Gestionada por proveedores externos
- **Ejemplos:** AWS, Microsoft Azure, Google Cloud Platform
- **Ventajas:** Escalabilidad, bajo costo inicial, sin mantenimiento
- **Desventajas:** Menor control, dependencia del proveedor

#### Nube Privada
- Infraestructura dedicada a una organización
- Mayor control y personalización
- **Ejemplos:** OpenStack, VMware vCloud, on-premise
- **Ventajas:** Control total, cumplimiento normativo
- **Desventajas:** Alto costo, requiere mantenimiento

#### Nube Híbrida
- Combinación de nube pública y privada
- Permite migración flexible de cargas de trabajo
- **Uso típico:** Datos sensibles en privada, procesamiento en pública

#### Nube Comunitaria
- Infraestructura compartida entre organizaciones con intereses comunes
- **Ejemplo:** Sector salud, instituciones gubernamentales

---

### ⚠️ RIESGOS TÍPICOS EN CLOUD

#### 1. Configuraciones Erróneas (Misconfiguration)
- **Problema más común (65% de las brechas)**
- Buckets S3 públicos
- ACLs mal definidas
- Grupos de seguridad abiertos (0.0.0.0/0)
- Snapshots públicos

#### 2. Gestión Deficiente de Credenciales
- Claves hardcodeadas en código fuente
- Secrets en repositorios públicos
- Credenciales con permisos excesivos
- Falta de rotación de claves

#### 3. Logs con Datos Sensibles
- Logs con información de usuarios
- Contraseñas en logs de aplicación
- Tokens de autenticación expuestos
- Logs sin cifrado

#### 4. Usuarios con Permisos Excesivos
- Violación del principio de mínimo privilegio
- Cuentas de servicio con permisos de admin
- Ausencia de MFA
- Falta de segregación de funciones

#### 5. Dependencia de Terceros
- Problemas de compliance
- Falta de visibilidad
- Cambios unilaterales de términos
- Dependencia tecnológica (vendor lock-in)

---

### 🛡️ CONTROLES ESENCIALES

#### Identity and Access Management (IAM)
- Principio de mínimo privilegio
- Autenticación multifactor (MFA) obligatoria
- Políticas basadas en roles (RBAC)
- Revisión periódica de permisos

#### Cifrado
- **En tránsito:** TLS 1.2+ obligatorio
- **En reposo:** AES-256 para datos sensibles
- Gestión de claves con KMS
- Cifrado de snapshots y backups

#### Logging y Monitoreo Centralizado
- **AWS:** CloudTrail, GuardDuty, Security Hub
- **Azure:** Azure Monitor, Security Center
- **GCP:** Cloud Logging, Security Command Center
- Alertas en tiempo real
- Retención de logs (mínimo 90 días)

#### Evaluación de Configuración
- Cloud Security Posture Management (CSPM)
- Auditorías automatizadas
- Compliance continuo
- Remediación automática

#### Backups y Snapshots Seguros
- Backups cifrados
- Almacenamiento en región diferente
- Pruebas de restauración periódicas
- Versionado de snapshots

---

### 🖥️ VIRTUALIZACIÓN Y SUS RIESGOS

#### Conceptos de Virtualización
- **Hipervisor Tipo 1:** Bare-metal (ESXi, Hyper-V, KVM)
- **Hipervisor Tipo 2:** Hosted (VirtualBox, VMware Workstation)

#### Riesgos Específicos

**1. VM Escape**
- Explotación de vulnerabilidades en el hipervisor
- Acceso del guest al host
- Compromiso de otras VMs

**2. Snapshots No Cifrados**
- Contienen datos sensibles
- Pueden ser copiados
- Persisten credenciales

**3. Redes Virtuales Sin Segmentación**
- Lateral movement facilitado
- Falta de micro-segmentación
- Ausencia de inspection del tráfico este-oeste

**4. Resource Exhaustion**
- DoS mediante consumo de recursos
- Falta de límites por VM
- Impacto en otras VMs (noisy neighbor)

#### Caso Real: Ataque VENOM
**CVE-2015-3456**
- Vulnerabilidad en QEMU/KVM
- Permitía escape de VM
- Afectó a millones de instancias
- **Lección:** Mantener hipervisores actualizados

---

### 📋 MARCO NORMATIVO

#### ISO 27017
- Controles de seguridad para servicios cloud
- Guía basada en ISO 27002
- Define responsabilidades entre proveedor y cliente

#### ISO 27018
- Protección de datos personales en nube pública
- Transparencia en el tratamiento de datos
- Derechos de los titulares de datos

#### NIST SP 800-144
- Cloud Computing Security Guidelines
- Mejores prácticas para adopción segura
- Framework de evaluación de riesgos

#### Normativa Argentina

**Ley 25.326 - Protección de Datos Personales**
- Regulación del tratamiento de datos
- Derechos de acceso, rectificación y supresión
- Obligaciones de seguridad

**Ley 27.078 - Argentina Digital**
- Neutralidad de la red
- Protección de datos de los usuarios
- Infraestructura de telecomunicaciones

**GDPR (Aplicable a datos de ciudadanos UE)**
- Right to be forgotten
- Data portability
- Privacy by design

---

### 📰 CASO REAL: NASA S3 LEAK (2018)

**Descripción del Incidente:**
- Exposición de logs de empleados de la NASA
- Bucket S3 con permisos públicos
- Acceso sin autenticación

**Causa Raíz:**
- ACL configurada como "Everyone: Read"
- Falta de revisión de permisos
- Ausencia de alertas de configuración pública

**Impacto:**
- Exposición de información sensible
- Datos personales de empleados
- Pérdida de reputación

**Lecciones Aprendidas:**
1. Revisar permisos ANTES de crear recursos
2. Implementar políticas preventivas (SCP)
3. Monitoreo continuo de configuraciones
4. Automatizar la detección de exposiciones

**Remediación:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "s3:x-amz-acl": ["public-read", "public-read-write"]
      }
    }
  }]
}
```

---

### 💡 MEJORES PRÁCTICAS

#### Diseño Seguro
- Security by design desde el inicio
- Zero Trust Architecture
- Defensa en profundidad
- Separación de entornos (dev/staging/prod)

#### Operación Segura
- Automatización de controles
- Infrastructure as Code (IaC)
- GitOps para gestión de infraestructura
- Pipelines de seguridad en CI/CD

#### Monitoreo y Respuesta
- SIEM integrado con cloud
- Playbooks de respuesta a incidentes
- Threat intelligence feeds
- Purple teaming periódico

#### Gestión de Vulnerabilidades
- Escaneo continuo de imágenes
- Parches automatizados
- Inventario de assets actualizado
- Vulnerability management program

---

## CIERRE TEÓRICO

> **Mensaje clave:**
> "La nube no elimina la seguridad: la multiplica."

**Principios fundamentales para recordar:**

1. **Responsabilidad compartida** - Conoce qué gestiona el proveedor y qué gestionas tú
2. **Mínimo privilegio** - Otorga solo los permisos necesarios
3. **Auditoría continua** - Lo que no se mide, no se puede mejorar
4. **Automatización** - Reduce el error humano
5. **Visibilidad total** - No puedes proteger lo que no ves

---

## 🧪 PARTE PRÁCTICA - LABORATORIO

### Objetivo General
Identificar configuraciones inseguras, crear políticas de acceso seguras y aplicar buenas prácticas de auditoría en entornos cloud y virtualizados.

### Requisitos

#### Software
- Python 3.8+
- boto3 (AWS SDK)
- awscli
- Docker (para LocalStack)
- VirtualBox o Proxmox (para virtualización)

#### Entornos
- Cuenta AWS (Free Tier) o LocalStack
- Entorno Linux/Kali/Ubuntu
- VSCode o IDE de preferencia
- Conexión a Internet

#### Conocimientos Previos
- Python básico
- CLI de Linux
- Conceptos de redes
- Fundamentos de AWS

---

### 📁 ESTRUCTURA DEL LABORATORIO

```
clase7/
├── README.md                          (este archivo)
├── scripts/
│   ├── detect_public_buckets.py      (Ejercicio 1)
│   ├── check_security_groups.py      (Script adicional)
│   ├── audit_iam_users.py            (Script adicional)
│   └── requirements.txt
├── docs/
│   ├── SETUP.md                      (Guía de configuración)
│   ├── EJERCICIOS.md                 (Guía detallada de ejercicios)
│   └── TROUBLESHOOTING.md
└── templates/
    ├── IAM_policy_example.json       (Ejercicio 2)
    ├── bucket_policy_secure.json
    └── reporte_template.md
```

---

### 🎯 EJERCICIOS

Los ejercicios se encuentran detallados en:
- **[docs/EJERCICIOS.md](docs/EJERCICIOS.md)** - Guía paso a paso
- **[docs/SETUP.md](docs/SETUP.md)** - Configuración del entorno

#### Resumen de Ejercicios:

1. **Escaneo de Configuraciones Inseguras**
   Script Python para detectar buckets S3 públicos

2. **Política IAM Segura**
   Creación de políticas con mínimo privilegio

3. **Simulación de Vulnerabilidad y Remediación**
   Crear exposición, detectar y remediar

4. **Seguridad en Entornos Virtualizados**
   Auditoría de VMs con nmap y hardening

---

### 📤 ENTREGA DEL LABORATORIO

**Archivo:** `reporte_cloud_security_<grupo>.pdf`

**Estructura del reporte:**

1. **Introducción**
   - Objetivos del laboratorio
   - Alcance del análisis

2. **Entorno**
   - Descripción de la infraestructura
   - Herramientas utilizadas

3. **Hallazgos**
   - Vulnerabilidades identificadas
   - Nivel de riesgo (Alto/Medio/Bajo)
   - Evidencias (capturas de pantalla)

4. **Mitigaciones**
   - Controles implementados
   - Configuraciones aplicadas
   - Verificación post-remediación

5. **Conclusiones**
   - Lecciones aprendidas
   - Recomendaciones para producción
   - Próximos pasos

**Plantilla disponible en:** [templates/reporte_template.md](templates/reporte_template.md)

---

## 🎓 RECURSOS ADICIONALES

### Documentación Oficial
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)

### Herramientas Open Source
- **ScoutSuite** - Multi-cloud security auditing
- **Prowler** - AWS security assessment
- **CloudSploit** - Cloud security scanner
- **Trivy** - Container vulnerability scanner

### Certificaciones Relevantes
- AWS Certified Security - Specialty
- Azure Security Engineer Associate
- Google Professional Cloud Security Engineer
- CCSK (Certificate of Cloud Security Knowledge)

### Libros Recomendados
- "Cloud Security and Privacy" - Tim Mather
- "AWS Security" - Dylan Shield
- "Kubernetes Security" - Liz Rice

---

## 🔍 CIERRE Y REFLEXIÓN FINAL

> "La nube no es insegura. Lo inseguro es no entender quién es responsable."

### Estadísticas para reflexionar:
- 90% de las brechas cloud son por errores humanos
- 67% de las organizaciones no tienen visibilidad completa de su infraestructura cloud
- El tiempo promedio para detectar una brecha es de 206 días

### Conclusiones clave:

1. **La seguridad es un proceso continuo**
   No es un producto que se compra, es una práctica que se cultiva

2. **La automatización es tu aliada**
   Pero la auditoría manual sigue siendo fundamental

3. **El auditor moderno combina:**
   - Técnica (conocimiento de herramientas)
   - Gestión (políticas y procesos)
   - Criterio humano (análisis de contexto)

4. **La responsabilidad compartida no es excusa**
   Aunque el proveedor gestione la infraestructura, tú gestionas la configuración

5. **La visibilidad es el primer paso**
   No puedes proteger lo que no conoces

---

## 📞 CONTACTO Y SOPORTE

**Instructor:** UTN - Laboratorio de Blockchain y Ciberseguridad

**Consultas:**
- Durante las clases prácticas
- Foro de la materia
- Email institucional

---

## 📄 LICENCIA

© 2025 – Universidad Tecnológica Nacional (UTN)
Laboratorio de Blockchain y Ciberseguridad

Material educativo de uso académico.

---

**Versión:** 1.0
**Última actualización:** Octubre 2025
**Autor:** UTN - Laboratorio de Ciberseguridad
