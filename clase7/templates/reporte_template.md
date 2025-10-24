# LABORATORIO CLASE 7
## SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN

---

**Universidad Tecnológica Nacional**
**Laboratorio de Blockchain y Ciberseguridad**

---

### INFORMACIÓN DEL ESTUDIANTE/GRUPO

- **Nombre/Grupo:** [Completar]
- **Legajo/s:** [Completar]
- **Fecha de realización:** [DD/MM/AAAA]
- **Fecha de entrega:** [DD/MM/AAAA]
- **Docente:** [Completar]

---

## ÍNDICE

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [Introducción](#2-introducción)
3. [Entorno de Laboratorio](#3-entorno-de-laboratorio)
4. [Ejercicio 1: Auditoría de Buckets S3](#4-ejercicio-1-auditoría-de-buckets-s3)
5. [Ejercicio 2: Políticas IAM](#5-ejercicio-2-políticas-iam)
6. [Ejercicio 3: Simulación y Remediación](#6-ejercicio-3-simulación-y-remediación)
7. [Ejercicio 4: Seguridad en Virtualización](#7-ejercicio-4-seguridad-en-virtualización)
8. [Ejercicios Adicionales](#8-ejercicios-adicionales-opcional)
9. [Análisis de Riesgos](#9-análisis-de-riesgos)
10. [Conclusiones y Recomendaciones](#10-conclusiones-y-recomendaciones)
11. [Referencias](#11-referencias)
12. [Anexos](#12-anexos)

---

## 1. RESUMEN EJECUTIVO

> **Instrucciones:** Breve resumen de 1 página que incluya:
> - Objetivo del laboratorio
> - Principales hallazgos
> - Vulnerabilidades identificadas (número y severidad)
> - Controles implementados
> - Conclusión general

### Hallazgos Principales

| Severidad | Cantidad | Remediado |
|-----------|----------|-----------|
| Crítico   | [#]      | Sí/No     |
| Alto      | [#]      | Sí/No     |
| Medio     | [#]      | Sí/No     |
| Bajo      | [#]      | Sí/No     |

### Métricas de Seguridad

- **Buckets S3 analizados:** [#]
- **Buckets públicos encontrados:** [#]
- **Security Groups auditados:** [#]
- **Reglas inseguras:** [#]
- **Usuarios IAM sin MFA:** [#]
- **VMs auditadas:** [#]
- **Servicios innecesarios encontrados:** [#]

---

## 2. INTRODUCCIÓN

### 2.1 Objetivos del Laboratorio

El presente laboratorio tiene como objetivos:

1. [Completar con objetivos específicos]
2. [...]
3. [...]

### 2.2 Alcance

**Incluido en el alcance:**
- [Listar lo que se incluyó]
- [...]

**Fuera del alcance:**
- [Listar lo que NO se incluyó]
- [...]

### 2.3 Metodología

Se siguió la siguiente metodología:

1. **Fase de Preparación:** Configuración del entorno
2. **Fase de Auditoría:** Identificación de vulnerabilidades
3. **Fase de Remediación:** Aplicación de controles
4. **Fase de Verificación:** Validación de controles
5. **Fase de Documentación:** Reporte de hallazgos

---

## 3. ENTORNO DE LABORATORIO

### 3.1 Infraestructura Cloud

- **Proveedor:** AWS / LocalStack
- **Región:** [us-east-1 / otra]
- **Cuenta/ID:** [Número de cuenta AWS o "LocalStack"]
- **Fecha de auditoría:** [DD/MM/AAAA]

#### Recursos Creados

| Tipo | Nombre | Propósito |
|------|--------|-----------|
| S3 Bucket | [nombre] | [propósito] |
| IAM User | [nombre] | [propósito] |
| IAM Policy | [nombre] | [propósito] |
| Security Group | [nombre] | [propósito] |

### 3.2 Entorno de Virtualización

- **Hipervisor:** VirtualBox / Proxmox / VMware
- **Versión:** [versión]
- **Red virtual:** [configuración]

#### Máquinas Virtuales

| VM | OS | IP | Rol |
|----|----|----|-----|
| VM1 | Ubuntu Server 22.04 | 192.168.56.10 | Target |
| VM2 | Kali Linux 2023.3 | 192.168.56.20 | Auditor |

### 3.3 Herramientas Utilizadas

| Herramienta | Versión | Propósito |
|-------------|---------|-----------|
| Python | 3.x | Scripting de auditoría |
| boto3 | x.x.x | SDK de AWS |
| AWS CLI | x.x.x | Interface de línea de comandos |
| nmap | x.x | Escaneo de red |
| [Otra] | [versión] | [propósito] |

---

## 4. EJERCICIO 1: AUDITORÍA DE BUCKETS S3

### 4.1 Objetivo

Identificar configuraciones inseguras en buckets S3 utilizando scripts de auditoría automatizados.

### 4.2 Procedimiento

#### 4.2.1 Creación de Buckets de Prueba

**Comandos ejecutados:**
```bash
[Pegar comandos utilizados]
```

**Resultado:**
[Describir resultado]

#### 4.2.2 Ejecución del Script de Auditoría

**Comando:**
```bash
python scripts/detect_public_buckets.py
```

**Captura de pantalla:**

![Ejecución del script](imagenes/ejercicio1-script.png)

> **Instrucciones:** Insertar captura de pantalla aquí

### 4.3 Hallazgos

#### Hallazgo #1: Bucket S3 Público

**Detalles:**
- **Bucket:** [nombre del bucket]
- **Severidad:** CRÍTICO
- **ACL:** AllUsers: READ
- **Bloqueo de acceso público:** Deshabilitado

**Evidencia:**
```json
{
  "bucket": "nombre-bucket",
  "is_public": true,
  "risk_level": "CRÍTICO",
  "permissions": [
    {
      "group": "AllUsers",
      "permission": "READ"
    }
  ]
}
```

**Impacto:**
- Exposición de datos sensibles
- Violación de principios de seguridad
- Incumplimiento normativo potencial

**Recomendación:**
- Remover permisos públicos
- Habilitar Block Public Access
- Implementar política de bucket restrictiva
- Habilitar cifrado

### 4.4 Resumen de Hallazgos - Ejercicio 1

| Bucket | Público | Riesgo | ACL Pública | Bloqueo Configurado |
|--------|---------|--------|-------------|---------------------|
| [nombre] | Sí/No | [nivel] | Sí/No | Sí/No |
| [nombre] | Sí/No | [nivel] | Sí/No | Sí/No |

### 4.5 Análisis

[Analizar los resultados obtenidos, explicar por qué son importantes y qué implicaciones tienen]

---

## 5. EJERCICIO 2: POLÍTICAS IAM

### 5.1 Objetivo

Implementar políticas IAM basadas en el principio de mínimo privilegio.

### 5.2 Procedimiento

#### 5.2.1 Análisis de Política de Ejemplo

**Política analizada:**
```json
[Pegar la política IAM aquí]
```

**Análisis:**

| Elemento | Descripción | Principio de Seguridad |
|----------|-------------|------------------------|
| Effect | [Allow/Deny] | [Explicar] |
| Action | [Acciones] | [Explicar por qué están permitidas] |
| Resource | [Recursos] | [Explicar alcance] |
| Condition | [Condiciones] | [Explicar restricción] |

#### 5.2.2 Creación de Usuario Restringido

**Comandos:**
```bash
[Pegar comandos de creación de usuario]
```

**Captura:**

![Creación de usuario IAM](imagenes/ejercicio2-user.png)

#### 5.2.3 Pruebas de Acceso

**Tabla de Resultados:**

| Acción | Comando | Resultado Esperado | Resultado Obtenido | ¿Cumple? |
|--------|---------|--------------------|--------------------|----------|
| Subir archivo | `aws s3 cp test.txt s3://bucket/` | Éxito | [Tu resultado] | ✓/✗ |
| Descargar | `aws s3 cp s3://bucket/test.txt .` | Éxito | [Tu resultado] | ✓/✗ |
| Eliminar | `aws s3 rm s3://bucket/test.txt` | Denegado | [Tu resultado] | ✓/✗ |
| Listar buckets | `aws s3 ls` | Denegado | [Tu resultado] | ✓/✗ |
| Modificar ACL | `aws s3api put-bucket-acl...` | Denegado | [Tu resultado] | ✓/✗ |

**Capturas de evidencia:**

![Prueba de acceso permitido](imagenes/ejercicio2-permitido.png)

![Prueba de acceso denegado](imagenes/ejercicio2-denegado.png)

### 5.3 Análisis

**Pregunta 1:** ¿Por qué es importante el principio de mínimo privilegio?

**Respuesta:** [Tu respuesta]

**Pregunta 2:** ¿Qué función cumple la condición `aws:SecureTransport`?

**Respuesta:** [Tu respuesta]

**Pregunta 3:** ¿Qué riesgos existen si un usuario tiene permisos excesivos?

**Respuesta:** [Tu respuesta]

---

## 6. EJERCICIO 3: SIMULACIÓN Y REMEDIACIÓN

### 6.1 Objetivo

Crear una vulnerabilidad intencional, detectarla y remediarla aplicando controles de seguridad.

### 6.2 Fase 1: Creación de Vulnerabilidad

#### 6.2.1 Bucket Vulnerable

**Configuración aplicada:**
```bash
[Comandos usados para crear vulnerabilidad]
```

**Evidencia de exposición pública:**

![Acceso público exitoso](imagenes/ejercicio3-vulnerable.png)

**Comando curl:**
```bash
curl https://[bucket].s3.amazonaws.com/datos-sensibles.txt
```

**Salida:**
```
[Contenido expuesto públicamente]
```

### 6.3 Fase 2: Detección

#### 6.3.1 Auditoría Automatizada

**Script ejecutado:**
```bash
python scripts/detect_public_buckets.py
```

**Hallazgos:**

![Detección de bucket público](imagenes/ejercicio3-deteccion.png)

**JSON de hallazgos:**
```json
[Pegar hallazgos específicos de este bucket]
```

### 6.4 Fase 3: Remediación

#### 6.4.1 Controles Aplicados

**Control 1: ACL Privada**
```bash
aws s3api put-bucket-acl --bucket [nombre] --acl private
```

**Verificación:**
```bash
aws s3api get-bucket-acl --bucket [nombre]
```

**Control 2: Block Public Access**
```bash
[Comando usado]
```

**Control 3: Política de Bucket**
```json
[Política aplicada]
```

**Control 4: Cifrado**
```bash
[Comando de cifrado]
```

**Control 5: Logging**
```bash
[Comando de logging]
```

### 6.5 Fase 4: Verificación

#### 6.5.1 Re-auditoría

**Script ejecutado nuevamente:**
```bash
python scripts/detect_public_buckets.py
```

**Resultado:**

![Bucket ahora seguro](imagenes/ejercicio3-remediado.png)

#### 6.5.2 Prueba de Acceso Público

**Comando:**
```bash
curl https://[bucket].s3.amazonaws.com/datos-sensibles.txt
```

**Resultado esperado:** Access Denied

**Resultado obtenido:**
```xml
[Pegar error de Access Denied]
```

### 6.6 Comparativa Antes/Después

| Control | Antes | Después |
|---------|-------|---------|
| ACL | Public-read-write | Private |
| Block Public Access | Deshabilitado | Habilitado (todas las opciones) |
| Política de bucket | Ninguna | Restrictiva |
| Cifrado | Deshabilitado | AES256 |
| Logging | Deshabilitado | Habilitado |
| Acceso público | ✓ Permitido | ✗ Denegado |

### 6.7 Análisis

[Explicar el proceso de remediación, lecciones aprendidas y mejores prácticas identificadas]

---

## 7. EJERCICIO 4: SEGURIDAD EN VIRTUALIZACIÓN

### 7.1 Objetivo

Auditar y aplicar hardening a máquinas virtuales en un entorno controlado.

### 7.2 Arquitectura del Entorno

**Diagrama de red:**

```
┌─────────────────┐         ┌─────────────────┐
│  Kali Linux     │         │ Ubuntu Server   │
│  (Auditor)      │─────────│  (Target)       │
│  192.168.56.20  │ LAN     │  192.168.56.10  │
└─────────────────┘         └─────────────────┘
        │                            │
        └────────────────────────────┘
              Red Interna: 192.168.56.0/24
```

> **Instrucciones:** Crear diagrama más detallado si es posible

### 7.3 Fase 1: Configuración Inicial

#### 7.3.1 Servicios Instalados en Target

| Servicio | Puerto | Estado | Propósito |
|----------|--------|--------|-----------|
| SSH | 22 | Activo | Administración remota |
| Apache | 80 | Activo | Servidor web |
| MySQL | 3306 | Activo | Base de datos |

### 7.4 Fase 2: Auditoría de Seguridad

#### 7.4.1 Verificación de Conectividad

**Comando:**
```bash
ping -c 4 192.168.56.10
```

**Resultado:**
```
[Pegar resultado del ping]
```

#### 7.4.2 Escaneo con Nmap

**Escaneo básico:**
```bash
nmap 192.168.56.10
```

**Resultado:**
```
[Pegar resultado completo]
```

**Captura:**

![Escaneo nmap básico](imagenes/ejercicio4-nmap-basico.png)

**Escaneo de versiones:**
```bash
nmap -sS -sV 192.168.56.10
```

**Resultado:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH [versión]
80/tcp   open  http    Apache httpd [versión]
3306/tcp open  mysql   MySQL [versión]
...
```

**Escaneo completo:**
```bash
nmap -A -T4 192.168.56.10 -oN scan_results.txt
```

**Archivo adjunto:** [Incluir scan_results.txt en anexos]

#### 7.4.3 Análisis de Vulnerabilidades

**Script de vulnerabilidades NSE:**
```bash
nmap --script vuln 192.168.56.10
```

**Hallazgos:**
```
[Pegar hallazgos de vulnerabilidades]
```

### 7.5 Fase 3: Documentación de Hallazgos

#### Hallazgo #1: MySQL Expuesto Externamente

**Severidad:** ALTO

**Descripción:**
MySQL está escuchando en 0.0.0.0 y accesible desde la red, lo que expone la base de datos a potenciales ataques de fuerza bruta o explotación de vulnerabilidades.

**Evidencia:**
```
3306/tcp open  mysql   MySQL 8.0.33
```

**Riesgo:**
- Acceso no autorizado a datos
- Ataques de fuerza bruta
- Explotación de vulnerabilidades conocidas

**Recomendación:**
- Configurar MySQL para escuchar solo en localhost
- Implementar firewall bloqueando acceso externo
- Usar autenticación fuerte

#### Hallazgo #2: [Otro hallazgo]

[Repetir estructura para cada hallazgo]

#### Resumen de Hallazgos

| #  | Servicio | Puerto | Severidad | Estado Inicial |
|----|----------|--------|-----------|----------------|
| 1  | MySQL | 3306 | Alto | Expuesto |
| 2  | SSH | 22 | Medio | Accesible |
| 3  | Apache | 80 | Bajo | Activo |

### 7.6 Fase 4: Hardening

#### 7.6.1 Configuración de Firewall

**Comandos ejecutados:**
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```

**Verificación:**
```bash
sudo ufw status verbose
```

**Resultado:**
```
[Pegar resultado]
```

**Captura:**

![Configuración UFW](imagenes/ejercicio4-ufw.png)

#### 7.6.2 Hardening de SSH

**Modificaciones realizadas en `/etc/ssh/sshd_config`:**

| Parámetro | Valor Anterior | Valor Nuevo | Justificación |
|-----------|----------------|-------------|---------------|
| PermitRootLogin | yes | no | Prevenir acceso directo como root |
| PasswordAuthentication | yes | no | Forzar uso de claves SSH |
| Port | 22 | 2222 | Reducir ataques automatizados |
| AllowUsers | [todos] | [usuario] | Restringir usuarios permitidos |

**Comando de reinicio:**
```bash
sudo systemctl restart sshd
```

#### 7.6.3 Hardening de MySQL

**Script de seguridad ejecutado:**
```bash
sudo mysql_secure_installation
```

**Opciones seleccionadas:**
- [x] Establecer contraseña de root
- [x] Remover usuarios anónimos
- [x] Deshabilitar login remoto de root
- [x] Remover base de datos de prueba
- [x] Recargar tablas de privilegios

**Configuración de bind-address:**
```bash
# /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1
```

#### 7.6.4 Servicios Deshabilitados

```bash
sudo systemctl stop apache2
sudo systemctl disable apache2
```

**Justificación:** [Explicar por qué se deshabilitó Apache]

### 7.7 Fase 5: Verificación Post-Hardening

#### 7.7.1 Re-escaneo

**Comando:**
```bash
nmap -sS -sV 192.168.56.10
```

**Resultado:**
```
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   closed   http
3306/tcp closed   mysql
```

**Captura:**

![Nmap post-hardening](imagenes/ejercicio4-nmap-post.png)

#### 7.7.2 Comparativa Antes/Después

| Puerto | Antes | Después | Control Aplicado |
|--------|-------|---------|------------------|
| 22/tcp | open | filtered | Firewall UFW |
| 80/tcp | open | closed | Servicio deshabilitado |
| 3306/tcp | open | closed | Firewall + bind localhost |

### 7.8 Snapshots y Respaldo

**Snapshot creado:**
- **Nombre:** post-hardening
- **Fecha:** [DD/MM/AAAA]
- **Descripción:** VM después de aplicar hardening

**Comando:**
```bash
VBoxManage snapshot "Ubuntu-Target" take "post-hardening"
```

**Exportación:**
```bash
VBoxManage export "Ubuntu-Target" -o ubuntu-target-hardened.ova
```

### 7.9 Análisis

[Analizar el proceso de hardening, explicar la efectividad de los controles y lecciones aprendidas]

---

## 8. EJERCICIOS ADICIONALES (OPCIONAL)

### 8.1 Auditoría de Security Groups

> Si realizaste este ejercicio, documenta aquí

### 8.2 Auditoría de Usuarios IAM

> Si realizaste este ejercicio, documenta aquí

---

## 9. ANÁLISIS DE RIESGOS

### 9.1 Matriz de Riesgos Identificados

| ID | Vulnerabilidad | Activo Afectado | Probabilidad | Impacto | Riesgo | Estado |
|----|----------------|-----------------|--------------|---------|--------|--------|
| R1 | Bucket S3 público | [bucket] | Alta | Alto | Crítico | Remediado |
| R2 | MySQL expuesto | Ubuntu-Target | Media | Alto | Alto | Remediado |
| R3 | Usuario sin MFA | IAM User | Media | Medio | Medio | Pendiente |

**Leyenda:**
- **Probabilidad:** Baja / Media / Alta
- **Impacto:** Bajo / Medio / Alto
- **Riesgo:** Bajo / Medio / Alto / Crítico

### 9.2 Análisis por Tipo de Riesgo

#### Riesgos de Configuración
[Analizar riesgos relacionados con configuración incorrecta]

#### Riesgos de Acceso
[Analizar riesgos de control de acceso]

#### Riesgos de Exposición
[Analizar riesgos de exposición de datos]

---

## 10. CONCLUSIONES Y RECOMENDACIONES

### 10.1 Conclusiones

**Conclusión 1: Configuraciones por defecto son inseguras**

[Elaborar sobre esta conclusión basándote en tus hallazgos]

**Conclusión 2: El principio de mínimo privilegio es fundamental**

[Elaborar]

**Conclusión 3: La auditoría continua es necesaria**

[Elaborar]

### 10.2 Lecciones Aprendidas

1. [Lección aprendida 1]
2. [Lección aprendida 2]
3. [Lección aprendida 3]

### 10.3 Mejores Prácticas Identificadas

#### Para Seguridad Cloud (AWS)

1. **Siempre habilitar Block Public Access** en buckets S3
   - Previene errores de configuración accidental
   - Añade capa adicional de protección

2. **Implementar MFA para todos los usuarios**
   - Especialmente para usuarios con privilegios
   - Usar MFA virtual o hardware

3. **Usar políticas IAM restrictivas**
   - Aplicar principio de mínimo privilegio
   - Revisar permisos regularmente

4. **Habilitar logging y monitoreo**
   - CloudTrail para auditoría
   - GuardDuty para detección de amenazas
   - Config para compliance

5. **Cifrar datos en reposo y en tránsito**
   - SSE-S3 o SSE-KMS para S3
   - TLS 1.2+ para comunicaciones

#### Para Virtualización

1. **Implementar segmentación de red**
   - Separar ambientes de producción y desarrollo
   - Usar VLANs y firewalls virtuales

2. **Aplicar hardening a VMs**
   - Configurar firewall local
   - Deshabilitar servicios innecesarios
   - Mantener sistema actualizado

3. **Gestionar snapshots de forma segura**
   - Cifrar snapshots con datos sensibles
   - Establecer política de retención
   - Probar restauración regularmente

4. **Monitorear hipervisores**
   - Mantener actualizados
   - Configurar alertas de seguridad
   - Revisar logs regularmente

### 10.4 Recomendaciones para Implementación en Producción

#### Corto Plazo (1-3 meses)

1. [Recomendación 1]
2. [Recomendación 2]
3. [Recomendación 3]

#### Mediano Plazo (3-6 meses)

1. [Recomendación 1]
2. [Recomendación 2]

#### Largo Plazo (6-12 meses)

1. [Recomendación 1]
2. [Recomendación 2]

### 10.5 Herramientas Recomendadas

| Herramienta | Categoría | Propósito | Costo |
|-------------|-----------|-----------|-------|
| AWS Config | Compliance | Auditoría continua | $$$ |
| ScoutSuite | Auditoría | Multi-cloud security audit | Gratis |
| Prowler | Auditoría | AWS security best practices | Gratis |
| Lynis | Hardening | System auditing | Gratis |

---

## 11. REFERENCIAS

### 11.1 Documentación Oficial

1. AWS Well-Architected Framework - Security Pillar
   https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/

2. AWS S3 Security Best Practices
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html

3. IAM Best Practices
   https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### 11.2 Estándares y Frameworks

1. ISO/IEC 27017:2015 - Cloud Security
2. NIST SP 800-144 - Guidelines on Security and Privacy in Public Cloud Computing
3. CIS AWS Foundations Benchmark
4. OWASP Cloud Security Project

### 11.3 Material del Curso

1. Clase 7 - Seguridad en la Nube y Virtualización - Contenido Teórico
2. Scripts de auditoría - Repositorio GitHub del curso

### 11.4 Bibliografía Adicional

1. [Libro/Artículo relevante]
2. [Otro recurso utilizado]

---

## 12. ANEXOS

### Anexo A: Código de Scripts

#### A.1 Script detect_public_buckets.py

```python
[Código completo del script o referencia al archivo]
```

#### A.2 Modificaciones Realizadas

```python
[Si realizaste modificaciones, documentarlas aquí]
```

### Anexo B: Políticas IAM Completas

#### B.1 IAM_policy_example.json

```json
[Política completa]
```

#### B.2 bucket_policy_secure.json

```json
[Política completa]
```

### Anexo C: Salidas Completas de Comandos

#### C.1 Salida completa de audit_results.json

```json
[Pegar JSON completo]
```

#### C.2 Salida completa de nmap

```
[Pegar scan_results.txt completo]
```

### Anexo D: Configuraciones de Sistema

#### D.1 Configuración de SSH (sshd_config)

```bash
[Contenido del archivo modificado]
```

#### D.2 Configuración de MySQL (mysqld.cnf)

```bash
[Contenido relevante]
```

#### D.3 Reglas de Firewall UFW

```bash
[Salida de ufw status verbose]
```

### Anexo E: Capturas de Pantalla Adicionales

> Incluir todas las capturas de pantalla referenciadas en el documento

### Anexo F: Logs Relevantes

```
[Si hay logs relevantes para análisis, incluirlos aquí]
```

---

## DECLARACIÓN DE AUTORÍA

Declaro que el presente trabajo ha sido realizado por mí/nosotros de manera autónoma, utilizando únicamente las fuentes citadas en el apartado de referencias. Todos los ejercicios fueron ejecutados en el entorno de laboratorio proporcionado y ninguna acción se realizó fuera del alcance autorizado.

**Firma/Nombre:**

[Nombre del estudiante/grupo]

**Fecha:**

[DD/MM/AAAA]

---

**FIN DEL REPORTE**

---

© 2025 – Universidad Tecnológica Nacional (UTN)
Laboratorio de Blockchain y Ciberseguridad
