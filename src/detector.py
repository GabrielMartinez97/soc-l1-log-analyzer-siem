"""
Motor de Detección y Correlación mapeado a MITRE ATT&CK (Fase 2 de un SIEM).

Aplica reglas de detección sobre los eventos normalizados (SSHAuthEvent y WebAccessEvent),
evaluando contexto crítico de un Analista SOC Nivel 1:
1. Umbrales de intentos fallidos (Brute Force vs Password Spraying).
2. Correlación de fallos seguidos de éxito (Account Compromise - CRITICAL).
3. Análisis de códigos HTTP (200 OK = posible explotación exitosa vs 403/404 = intento bloqueado).
"""

from collections import defaultdict
from dataclasses import dataclass, field
import re
from typing import Dict, List, Set

from src.parsers import SSHAuthEvent, WebAccessEvent


@dataclass
class SecurityAlert:
    """Representa una alerta generada por el Mini-SIEM lista para triaje SOC L1."""

    rule_id: str
    title: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    source_ip: str
    target_Asset_or_uri: str
    outcome: str           # BLOCKED / FAILED_ATTEMPT | SUCCESSFUL_EXPLOITATION
    description: str
    evidence_logs: List[str] = field(default_factory=list)
    recommended_action: str = ""


# Umbrales configurables para detección SSH
BRUTE_FORCE_THRESHOLD = 5
PASSWORD_SPRAY_USER_THRESHOLD = 4


def detect_ssh_threats(events: List[SSHAuthEvent]) -> List[SecurityAlert]:
    """
    Correlaciona eventos de autenticación SSH para detectar:
    - SOC-SSH-001: Fuerza Bruta SSH (T1110.001)
    - SOC-SSH-002: Password Spraying (T1110.003)
    - SOC-SSH-003: Compromiso de Cuenta tras Fuerza Bruta (T1078)
    """
    alerts: List[SecurityAlert] = []

    failed_by_ip: Dict[str, List[SSHAuthEvent]] = defaultdict(list)
    targeted_users_by_ip: Dict[str, Set[str]] = defaultdict(set)
    compromised_events: List[SSHAuthEvent] = []

    for event in events:
        if event.event_type == "FAILED_LOGIN":
            failed_by_ip[event.source_ip].append(event)
            targeted_users_by_ip[event.source_ip].add(event.username)

        elif event.event_type == "ACCEPTED_LOGIN":
            # Regla de correlación SOC-SSH-003:
            # Si una IP tenía múltiples intentos fallidos previos y luego logra entrar (Accepted)
            prior_failures = failed_by_ip.get(event.source_ip, [])
            if len(prior_failures) >= 3:
                compromised_events.append(event)

    # Generar alertas por Fuerza Bruta / Password Spraying por cada IP sospechosa
    for ip, failed_list in failed_by_ip.items():
        if len(failed_list) < BRUTE_FORCE_THRESHOLD:
            continue

        unique_users = targeted_users_by_ip[ip]
        hostname = failed_list[0].hostname
        evidence = [e.raw_log for e in failed_list]

        # Distinguir entre Password Spraying (muchos usuarios distintos, pocos intentos por usuario)
        # y Fuerza Bruta clásica (insistencia sobre pocos usuarios o ráfaga general)
        if len(unique_users) >= PASSWORD_SPRAY_USER_THRESHOLD and len(failed_list) == len(unique_users):
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-SSH-002",
                    title="SSH Password Spraying Detectado",
                    severity="HIGH",
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110.003",
                    mitre_technique_name="Brute Force: Password Spraying",
                    source_ip=ip,
                    target_Asset_or_uri=hostname,
                    outcome="FAILED_ATTEMPT",
                    description=(
                        f"La IP {ip} realizó {len(failed_list)} intentos fallidos probando "
                        f"{len(unique_users)} usuarios distintos ({', '.join(sorted(unique_users))}) "
                        f"para evitar bloqueos por cuenta."
                    ),
                    evidence_logs=evidence,
                    recommended_action=(
                        "Bloquear IP en firewall perimetral y verificar que las cuentas enumeradas "
                        "no existan o tengan MFA / autenticación por llave pública obligatoria."
                    ),
                )
            )
        else:
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-SSH-001",
                    title="Ataque de Fuerza Bruta SSH",
                    severity="MEDIUM",
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Brute Force: Password Guessing",
                    source_ip=ip,
                    target_Asset_or_uri=hostname,
                    outcome="FAILED_ATTEMPT",
                    description=(
                        f"La IP {ip} generó {len(failed_list)} intentos de inicio de sesión fallidos "
                        f"contra el host {hostname} (usuarios atacados: {', '.join(sorted(unique_users))})."
                    ),
                    evidence_logs=evidence,
                    recommended_action=(
                        "Verificar si la IP pertenece a una red conocida; de lo contrario, "
                        "agregar a lista de bloqueo (Blacklist / Fail2Ban)."
                    ),
                )
            )

    # Generar alerta CRÍTICA si hubo login exitoso tras fuerza bruta
    for comp_event in compromised_events:
        prior_failures = failed_by_ip[comp_event.source_ip]
        evidence = [e.raw_log for e in prior_failures[-3:]] + [comp_event.raw_log]
        alerts.append(
            SecurityAlert(
                rule_id="SOC-SSH-003",
                title="COMPROMISO DE CUENTA: Login SSH Exitoso tras Fuerza Bruta",
                severity="CRITICAL",
                mitre_tactic="Initial Access / Persistence",
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
                source_ip=comp_event.source_ip,
                target_Asset_or_uri=f"{comp_event.hostname} (user: {comp_event.username})",
                outcome="SUCCESSFUL_EXPLOITATION",
                description=(
                    f"¡ALERTA CRÍTICA! Tras {len(prior_failures)} intentos fallidos de fuerza bruta, "
                    f"la IP {comp_event.source_ip} logró autenticarse exitosamente (Accepted {comp_event.auth_method}) "
                    f"con el usuario '{comp_event.username}' en el servidor '{comp_event.hostname}'."
                ),
                evidence_logs=evidence,
                recommended_action=(
                    "ESCALAR INMEDIATAMENTE A SOC L2 / IR: 1) Desconectar sesión activa del usuario "
                    f"'{comp_event.username}', 2) Rotar credenciales, 3) Aislar el host '{comp_event.hostname}' "
                    "y auditar comandos ejecutados post-compromiso."
                ),
            )
        )

    return alerts


# Patrones de detección Web (aplicados sobre decoded_uri y user_agent)
SCANNER_UA_REGEX = re.compile(r"(nikto|nmap|sqlmap|nessus|acunetix|masscan|dirbuster|gobuster)", re.IGNORECASE)
SQLI_REGEX = re.compile(r"(union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|--\s*$|information_schema)", re.IGNORECASE)
PATH_TRAVERSAL_REGEX = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini)", re.IGNORECASE)
XSS_REGEX = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.IGNORECASE)
CMD_INJECTION_REGEX = re.compile(r"(;|\||&&|\$\()\s*(cat|nc|bash|sh|whoami|wget|curl)\b", re.IGNORECASE)


def detect_web_threats(events: List[WebAccessEvent]) -> List[SecurityAlert]:
    """
    Analiza peticiones HTTP normalizadas para detectar ataques web y evaluar si tuvieron
    éxito según el código de estado HTTP (200 OK vs 403/404/500).
    """
    alerts: List[SecurityAlert] = []
    scanner_events_by_ip: Dict[str, List[WebAccessEvent]] = defaultdict(list)

    for event in events:
        target_payload = f"{event.decoded_uri} {event.user_agent}"
        is_http_200 = event.status_code == 200
        outcome = (
            f"SUCCESSFUL_EXPLOITATION (HTTP {event.status_code} - {event.response_bytes} bytes enviados)"
            if is_http_200
            else f"BLOCKED_OR_FAILED (HTTP {event.status_code})"
        )

        # 1. Detección de SQL Injection (SOC-WEB-002)
        if SQLI_REGEX.search(event.decoded_uri):
            severity = "CRITICAL" if is_http_200 else "HIGH"
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-WEB-002",
                    title="Ataque de SQL Injection (SQLi) Detectado",
                    severity=severity,
                    mitre_tactic="Initial Access",
                    mitre_technique_id="T1190",
                    mitre_technique_name="Exploit Public-Facing Application",
                    source_ip=event.source_ip,
                    target_Asset_or_uri=event.decoded_uri,
                    outcome=outcome,
                    description=(
                        f"Se detectó un payload de inyección SQL desde {event.source_ip} hacia "
                        f"'{event.decoded_uri}'. El servidor respondió con código HTTP {event.status_code} "
                        f"y {event.response_bytes} bytes."
                    ),
                    evidence_logs=[event.raw_log],
                    recommended_action=(
                        "ESCALAR A SOC L2: El servidor devolvió HTTP 200 con alto volumen de bytes "
                        "(posible exfiltración de tabla de usuarios). Revisar base de datos y activar regla WAF."
                        if is_http_200
                        else "Bloquear IP en el WAF y verificar parametrización de consultas SQL."
                    ),
                )
            )
            continue

        # 2. Detección de Path Traversal / LFI (SOC-WEB-003)
        if PATH_TRAVERSAL_REGEX.search(event.decoded_uri):
            severity = "CRITICAL" if is_http_200 else "HIGH"
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-WEB-003",
                    title="Intento de Path Traversal / Local File Inclusion (LFI)",
                    severity=severity,
                    mitre_tactic="Initial Access / Collection",
                    mitre_technique_id="T1083",
                    mitre_technique_name="File and Directory Discovery",
                    source_ip=event.source_ip,
                    target_Asset_or_uri=event.decoded_uri,
                    outcome=outcome,
                    description=(
                        f"La IP {event.source_ip} intentó leer archivos del sistema operativo mediante "
                        f"secuencias de salto de directorio ('{event.decoded_uri}'). "
                        f"Respuesta del servidor: HTTP {event.status_code} ({event.response_bytes} bytes)."
                    ),
                    evidence_logs=[event.raw_log],
                    recommended_action=(
                        "ESCALAR A SOC L2: El servidor respondió HTTP 200 OK (el archivo fue leído por el atacante). "
                        "Parchear endpoint vulnerable y bloquear IP."
                        if is_http_200
                        else "El servidor bloqueó la lectura (HTTP 403/404). Monitorear y bloquear IP en WAF."
                    ),
                )
            )
            continue

        # 3. Detección de Cross-Site Scripting XSS (SOC-WEB-004)
        if XSS_REGEX.search(event.decoded_uri):
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-WEB-004",
                    title="Ataque Cross-Site Scripting (XSS) Detectado",
                    severity="HIGH" if is_http_200 else "MEDIUM",
                    mitre_tactic="Initial Access",
                    mitre_technique_id="T1189",
                    mitre_technique_name="Drive-by Compromise",
                    source_ip=event.source_ip,
                    target_Asset_or_uri=event.decoded_uri,
                    outcome=outcome,
                    description=(
                        f"Se detectó inyección de script malicioso orientado a robo de sesión/cookies "
                        f"desde {event.source_ip} en '{event.decoded_uri}'."
                    ),
                    evidence_logs=[event.raw_log],
                    recommended_action=(
                        "Bloquear dominio de comando y control (C2) referenciado en el script y sanitizar entrada."
                    ),
                )
            )
            continue

        # 4. Detección de OS Command Injection / RCE (SOC-WEB-005)
        if CMD_INJECTION_REGEX.search(event.decoded_uri):
            alerts.append(
                SecurityAlert(
                    rule_id="SOC-WEB-005",
                    title="Intento de Ejecución Remota de Comandos (OS Command Injection)",
                    severity="CRITICAL",
                    mitre_tactic="Execution",
                    mitre_technique_id="T1059.004",
                    mitre_technique_name="Command and Scripting Interpreter: Unix Shell",
                    source_ip=event.source_ip,
                    target_Asset_or_uri=event.decoded_uri,
                    outcome=outcome,
                    description=(
                        f"La IP {event.source_ip} intentó inyectar comandos de sistema y establecer una "
                        f"Reverse Shell con netcat ('{event.decoded_uri}'). Código HTTP: {event.status_code}."
                    ),
                    evidence_logs=[event.raw_log],
                    recommended_action=(
                        "Verificar conexiones salientes hacia la IP atacante en el puerto 4444 y "
                        "aislar el servidor web si existe proceso hijo de shell activo."
                    ),
                )
            )
            continue

        # 5. Agrupación de Escaneo Automatizado de Vulnerabilidades (SOC-WEB-001)
        if SCANNER_UA_REGEX.search(target_payload):
            scanner_events_by_ip[event.source_ip].append(event)

    for ip, scan_list in scanner_events_by_ip.items():
        uris = ", ".join(e.decoded_uri for e in scan_list)
        alerts.append(
            SecurityAlert(
                rule_id="SOC-WEB-001",
                title="Escaneo Automatizado de Vulnerabilidades (Nikto / Nmap)",
                severity="MEDIUM",
                mitre_tactic="Reconnaissance",
                mitre_technique_id="T1595.002",
                mitre_technique_name="Active Scanning: Vulnerability Scanning",
                source_ip=ip,
                target_Asset_or_uri=f"Múltiples rutas ({uris})",
                outcome="RECONNAISSANCE_BLOCKED (HTTP 403/404)",
                description=(
                    f"Se detectó reconocimiento activo con herramientas automatizadas (Nikto/Nmap) "
                    f"desde la IP {ip} realizando {len(scan_list)} peticiones a rutas sensibles ({uris})."
                ),
                evidence_logs=[e.raw_log for e in scan_list],
                recommended_action=(
                    "Bloquear IP en firewall/WAF por reconocimiento activo; confirmar que ninguna ruta "
                    "sensible (.env, phpmyadmin, backups) haya respondido con código 200."
                ),
            )
        )

    return alerts
