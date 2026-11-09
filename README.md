# 🛡️ SOC L1 Mini-SIEM & Log Triage Engine (MITRE ATT&CK)

![Role](https://img.shields.io/badge/Role-SOC%20Analyst%20L1-0A66C2?style=flat-square)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-D9381E?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square)

Motor ligero de análisis de logs, correlación de eventos y generación automatizada de reportes de triaje diseñado para simular el flujo real de trabajo de un **Analista de Ciberseguridad SOC Nivel 1 (Tier 1)**.

---

## 🎯 Objetivo del Proyecto (Perspectiva SOC L1)

En un **Security Operations Center (SOC)**, el analista Nivel 1 es la primera línea de defensa. Sus responsabilidades principales son:
1. **Monitorear y analizar logs** de autenticación (`auth.log`) y servidores web (`access.log`).
2. **Distinguir Falsos Positivos (FP) de Verdaderos Positivos (TP)** analizando el contexto (ej. códigos de respuesta HTTP `200 OK` vs `404/403`, o múltiples intentos fallidos seguidos de un inicio de sesión exitoso).
3. **Mapear alertas al framework MITRE ATT&CK** para clasificar la táctica y técnica del adversario.
4. **Aplicar Defanging a los IOCs** (`185.220.101[.]45`) para evitar clics accidentales y **documentar el ticket de escalado a SOC L2**.

---

## 🏗️ Arquitectura del Flujo de Triaje

```mermaid
flowchart LR
    A["Logs Crudos\n(linux_auth.log / web_access.log)"] --> B["Parsers & Normalización\n(Extracción de IP, Usuario, URI, Status)"]
    B --> C["Motor de Detección & Correlación\n(Reglas + Umbrales + Contexto)"]
    C --> D["Mapeo MITRE ATT&CK\n(Táctica, Técnica, Severidad)"]
    D --> E["Generador de Reporte SOC L1\n(IOCs Defanged + Playbook L2)"]
```

---

## 🗺️ Matriz de Detección MITRE ATT&CK Implementada

| ID Regla | Amenaza Detectada | Fuente de Log | Táctica MITRE | Técnica MITRE | Severidad |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SOC-SSH-001` | **SSH Brute Force Attack** | `linux_auth.log` | Credential Access | `T1110.001` - Password Guessing | `MEDIUM` |
| `SOC-SSH-002` | **SSH Password Spraying** | `linux_auth.log` | Credential Access | `T1110.003` - Password Spraying | `HIGH` |
| `SOC-SSH-003` | **Account Compromise Post-Brute Force** | `linux_auth.log` | Initial Access / Persistence | `T1078` - Valid Accounts | `CRITICAL` |
| `SOC-WEB-001` | **Automated Vulnerability Scanning (Nikto/Nmap/Sqlmap)** | `web_access.log` | Reconnaissance | `T1595.002` - Vulnerability Scanning | `LOW` / `MEDIUM` |
| `SOC-WEB-002` | **SQL Injection (SQLi) Attempt / Exploitation** | `web_access.log` | Initial Access | `T1190` - Exploit Public-Facing Application | `HIGH` / `CRITICAL` |
| `SOC-WEB-003` | **Path Traversal / Local File Inclusion (LFI)** | `web_access.log` | Initial Access / Collection | `T1190` / `T1083` - File and Directory Discovery | `HIGH` / `CRITICAL` |
| `SOC-WEB-004` | **Cross-Site Scripting (XSS) Payload** | `web_access.log` | Initial Access | `T1189` - Drive-by Compromise | `MEDIUM` |
| `SOC-WEB-005` | **OS Command Injection (RCE Attempt)** | `web_access.log` | Execution | `T1059.004` - Unix Shell | `CRITICAL` |

---

## 📂 Estructura del Proyecto

```text
soc-l1-log-analyzer-siem/
├── logs/
│   ├── linux_auth.log          # Dataset realista de eventos SSH y PAM en Linux
│   └── web_access.log          # Dataset realista de peticiones HTTP (Nginx/Apache)
├── src/
│   ├── __init__.py
│   ├── parsers.py              # Normalización de logs crudos con Regex
│   ├── detector.py             # Motor de reglas y correlación mapeado a MITRE ATT&CK
│   └── reporter.py             # Defanging de IOCs y generador de reporte de incidente
├── playbooks/
│   └── SOC_L1_Playbook.md      # Guía operativa de respuesta y escalado para el analista
├── reports/
│   ├── SOC_L1_Incident_Report.md # Reporte de triaje generado automáticamente
│   └── soc_alerts.json         # Alertas exportadas en formato JSON (integración SOAR)
├── tests/
│   └── test_siem.py            # Pruebas unitarias de parsers, reglas y defanging
├── main.py                     # CLI principal de ejecución del Mini-SIEM
└── README.md
```

---

## 🚀 Ejecución Rápida (CLI y Pruebas)

1. **Ejecutar el análisis completo de logs y generar el reporte de incidente:**
   ```bash
   python main.py
   ```
   **Salida en consola:**
   ```text
   ==============================================================================
     SOC L1 MINI-SIEM & LOG TRIAGE ENGINE — MITRE ATT&CK CORRELATOR
   ==============================================================================
   [+] Eventos SSH normalizados (logs\linux_auth.log): 17
   [+] Eventos Web normalizados (logs\web_access.log): 13
   ------------------------------------------------------------------------------
   [!] Total de Alertas de Seguridad Detectadas: 10

   SEV        | RULE ID      | MITRE      | IOC (DEFANGED)     | TITLE
   -----------------------------------------------------------------------------------------------
   CRITICAL   | SOC-SSH-003  | T1078      | 185.220.101[.]45   | COMPROMISO DE CUENTA: Login SSH Exitoso tras Fuerza Bruta
   CRITICAL   | SOC-WEB-002  | T1190      | 198.51.100[.]77    | Ataque de SQL Injection (SQLi) Detectado
   CRITICAL   | SOC-WEB-002  | T1190      | 198.51.100[.]77    | Ataque de SQL Injection (SQLi) Detectado
   CRITICAL   | SOC-WEB-003  | T1083      | 198.51.100[.]77    | Intento de Path Traversal / Local File Inclusion (LFI)
   CRITICAL   | SOC-WEB-005  | T1059.004  | 203.0.113[.]88     | Intento de Ejecución Remota de Comandos (OS Command Injection)
   HIGH       | SOC-SSH-002  | T1110.003  | 45.155.205[.]109   | SSH Password Spraying Detectado
   HIGH       | SOC-WEB-003  | T1083      | 198.51.100[.]77    | Intento de Path Traversal / Local File Inclusion (LFI)
   HIGH       | SOC-WEB-004  | T1189      | 203.0.113[.]88     | Ataque Cross-Site Scripting (XSS) Detectado
   MEDIUM     | SOC-SSH-001  | T1110.001  | 185.220.101[.]45   | Ataque de Fuerza Bruta SSH
   MEDIUM     | SOC-WEB-001  | T1595.002  | 91.240.118[.]222   | Escaneo Automatizado de Vulnerabilidades (Nikto / Nmap)
   ```

2. **Ejecutar la suite de pruebas unitarias:**
   ```bash
   python -m unittest discover -s tests -v
   ```

3. **Consultar artefactos operativos:**
   * 📄 [Ver Reporte de Triaje SOC L1 Generado](reports/SOC_L1_Incident_Report.md)
   * 📘 [Ver Playbook Operativo SOC L1 (Red + Host + Identidad)](playbooks/SOC_L1_Playbook.md)

---

## 👤 Autor

* **Gabriel Martínez** ([@GabrielMartinez97](https://github.com/GabrielMartinez97)) — *Cybersecurity SOC L1 Portfolio*
