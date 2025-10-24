# LABORATORIO DE CIBERSEGURIDAD 2025

## Universidad Tecnológica Nacional - FRVM
### Facultad Regional Villa María
### Laboratorio de Blockchain y Ciberseguridad

---

## DESCRIPCIÓN

Este repositorio contiene el material de laboratorio para el curso de Ciberseguridad de la UTN FRVM (Facultad Regional Villa María). Incluye ejercicios prácticos, scripts de auditoría, herramientas y documentación para cada clase del programa.

El curso cubre aspectos fundamentales y avanzados de la seguridad informática, con énfasis en aplicaciones prácticas y casos reales.

---

## ESTRUCTURA DEL REPOSITORIO

```
lab_cybersecurity_2025/
├── README.md                    # Este archivo
├── LICENSE                      # Licencia del proyecto
│
├── clase1/                      # (Próximamente)
│   └── ...
│
├── clase7/                      # Seguridad en la Nube y Virtualización
│   ├── README.md               # Teoría completa de la clase
│   ├── setup.sh                # Script de configuración automática
│   ├── scripts/                # Scripts de auditoría
│   │   ├── detect_public_buckets.py
│   │   ├── check_security_groups.py
│   │   ├── audit_iam_users.py
│   │   └── requirements.txt
│   ├── docs/                   # Documentación y guías
│   │   ├── SETUP.md
│   │   ├── EJERCICIOS.md
│   │   └── TROUBLESHOOTING.md
│   └── templates/              # Plantillas y ejemplos
│       ├── IAM_policy_example.json
│       ├── bucket_policy_secure.json
│       └── reporte_template.md
│
└── ... (otras clases se agregarán progresivamente)
```

---

## CONTENIDO POR CLASE

### Clase 7: Seguridad en la Nube y Virtualización

**Temas cubiertos:**
- Modelos de servicio cloud (IaaS, PaaS, SaaS)
- Shared Responsibility Model
- Auditoría de configuraciones de AWS S3
- Políticas IAM y principio de mínimo privilegio
- Security Groups y controles de red
- Auditoría de máquinas virtuales
- Hardening de sistemas Linux
- Detección y remediación de vulnerabilidades

**Ejercicios prácticos:**
1. Escaneo de configuraciones inseguras en S3
2. Implementación de políticas IAM seguras
3. Simulación de vulnerabilidad y remediación
4. Auditoría de seguridad en entornos virtualizados

**Tecnologías utilizadas:**
- AWS (S3, IAM, Security Groups)
- Python + boto3
- LocalStack (alternativa local)
- VirtualBox/Proxmox
- Nmap
- Linux (Ubuntu/Kali)

**📁 [Ir a Clase 7](clase7/)**

---

## REQUISITOS GENERALES

### Software Base
- Python 3.8 o superior
- Git
- Editor de texto (VSCode recomendado)
- Cuenta AWS (Free Tier) o LocalStack
- VirtualBox (para ejercicios de virtualización)

### Conocimientos Previos
- Fundamentos de redes
- Linux básico (línea de comandos)
- Programación básica en Python
- Conceptos básicos de ciberseguridad

---

## INICIO RÁPIDO

### 1. Clonar el Repositorio

```bash
git clone https://github.com/tu-usuario/lab_cybersecurity_2025.git
cd lab_cybersecurity_2025
```

### 2. Navegar a la Clase Deseada

```bash
cd clase7
```

### 3. Ejecutar Configuración Automática

```bash
./setup.sh
```

Este script:
- Verifica requisitos del sistema
- Crea entorno virtual de Python
- Instala dependencias
- Configura permisos de scripts
- Verifica configuración de AWS

### 4. Seguir la Documentación

Cada clase incluye documentación detallada:
- **README.md** - Teoría completa
- **docs/SETUP.md** - Guía de configuración
- **docs/EJERCICIOS.md** - Guía paso a paso de ejercicios
- **docs/TROUBLESHOOTING.md** - Solución de problemas

---

## METODOLOGÍA DE TRABAJO

### Estructura de Cada Clase

1. **Parte Teórica**
   - Conceptos fundamentales
   - Marco normativo
   - Casos reales

2. **Parte Práctica**
   - Ejercicios guiados
   - Scripts de auditoría
   - Análisis de resultados

3. **Entrega**
   - Reporte técnico
   - Evidencias (capturas)
   - Análisis y conclusiones

### Flujo de Trabajo Recomendado

```
1. Leer teoría (README.md)
           ↓
2. Configurar entorno (SETUP.md)
           ↓
3. Realizar ejercicios (EJERCICIOS.md)
           ↓
4. Documentar hallazgos (reporte_template.md)
           ↓
5. Revisar y entregar
```

---

## HERRAMIENTAS Y RECURSOS

### Herramientas Utilizadas en el Curso

| Herramienta | Propósito | Clase(s) |
|-------------|-----------|----------|
| Nmap | Escaneo de red | 4, 7 |
| Wireshark | Análisis de tráfico | 3, 5 |
| Metasploit | Pentesting | 6 |
| AWS CLI | Gestión de cloud | 7 |
| boto3 | SDK de AWS para Python | 7 |
| Docker | Contenedorización | 7 |
| VirtualBox | Virtualización | 7, 8 |

### Recursos Adicionales

**Documentación oficial:**
- [AWS Documentation](https://docs.aws.amazon.com/)
- [OWASP](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

**Certificaciones relevantes:**
- CompTIA Security+
- AWS Certified Security - Specialty
- CEH (Certified Ethical Hacker)
- CISSP

**Libros recomendados:**
- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "Hacking: The Art of Exploitation" - Jon Erickson
- "Cloud Security and Privacy" - Tim Mather

---

## CONTRIBUIR

### Reportar Problemas

Si encuentras errores o tienes sugerencias:

1. Abre un [Issue](https://github.com/tu-usuario/lab_cybersecurity_2025/issues)
2. Describe el problema claramente
3. Incluye pasos para reproducir
4. Adjunta logs o capturas si es relevante

### Mejoras y Contribuciones

Las contribuciones son bienvenidas:

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/mejora`)
3. Commit tus cambios (`git commit -am 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/mejora`)
5. Abre un Pull Request

---

## CÓDIGO DE CONDUCTA

Este es un entorno de aprendizaje académico:

✅ **Permitido:**
- Auditoría de sistemas propios o con autorización explícita
- Uso de laboratorios controlados (LocalStack, VMs propias)
- Compartir conocimiento y ayudar a compañeros
- Reportar vulnerabilidades de forma responsable

❌ **Prohibido:**
- Acceso no autorizado a sistemas
- Distribución de malware
- Explotación de vulnerabilidades sin permiso
- Violación de términos de servicio de proveedores

**Recuerda:** Con gran poder viene gran responsabilidad. Usa tus conocimientos de forma ética.

---

## LICENCIA

Este proyecto está bajo la licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

**Resumen:**
- ✅ Uso comercial
- ✅ Modificación
- ✅ Distribución
- ✅ Uso privado
- ⚠️ Sin garantía
- ⚠️ Atribución requerida

---

## CONTACTO

**Universidad Tecnológica Nacional - FRVM**
**Facultad Regional Villa María**
Laboratorio de Blockchain y Ciberseguridad

- **Email:** fboiero@frvm.utn.edu.ar
- **Sitio web:** [https://www.frvm.utn.edu.ar](https://www.frvm.utn.edu.ar)
- **GitHub:** [https://github.com/fboiero/lab_cybersecurity_2025](https://github.com/fboiero/lab_cybersecurity_2025)

---

## DISCLAIMER

Este material es exclusivamente para fines educativos. Las técnicas y herramientas presentadas deben usarse únicamente en entornos controlados y con autorización explícita.

El uso indebido de estas herramientas puede ser ilegal. Los autores y la institución no se hacen responsables del mal uso de este material.

**Siempre:**
- Obtén autorización antes de realizar pruebas de seguridad
- Respeta la privacidad y la propiedad intelectual
- Sigue las leyes locales e internacionales
- Actúa de forma ética y profesional

---

## AGRADECIMIENTOS

- Equipo docente de la UTN
- Estudiantes por feedback y mejoras
- Comunidad open-source de ciberseguridad
- AWS por el programa educativo
- Todos los que contribuyen al conocimiento libre

---

## ACTUALIZACIONES

- **v1.0** (Octubre 2025) - Clase 7 completada
- Próximamente: Clases 1-6 y 8-12

---

## ROADMAP

### Próximas Adiciones

- [ ] Clase 1: Introducción a la Ciberseguridad
- [ ] Clase 2: Criptografía Aplicada
- [ ] Clase 3: Análisis de Tráfico de Red
- [ ] Clase 4: Escaneo y Enumeración
- [ ] Clase 5: Vulnerabilidades Web
- [ ] Clase 6: Pentesting y Explotación
- [ ] Clase 8: Forense Digital
- [ ] Clase 9: Malware Analysis
- [ ] Clase 10: Respuesta a Incidentes
- [ ] Clase 11: Gestión de Riesgos
- [ ] Clase 12: Compliance y Normativa

### Mejoras Planeadas

- [ ] Videos tutoriales
- [ ] Entorno Dockerizado completo
- [ ] Más ejercicios opcionales
- [ ] Challenges CTF
- [ ] Integración con plataforma de aprendizaje

---

**¡Bienvenido al laboratorio! Que tu aprendizaje sea productivo y seguro.**

---

© 2025 - Universidad Tecnológica Nacional - FRVM (Facultad Regional Villa María)
Laboratorio de Blockchain y Ciberseguridad
