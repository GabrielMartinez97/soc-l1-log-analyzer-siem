"""
Módulo de Parsing y Normalización de Logs (Fase 1 de un SIEM).

En un SOC Nivel 1, antes de aplicar reglas de detección, los logs crudos (raw logs)
de distintas fuentes deben ser normalizados en campos estructurados:
- IP de origen (source_ip)
- Marca de tiempo (timestamp)
- Usuario afectado (username)
- Acción / Resultado (status_code, event_type)
- Payload decodificado (decoded_uri) para evitar evasión por URL-encoding (%20, %2F, etc.)
"""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import List, Optional
from urllib.parse import unquote


@dataclass
class SSHAuthEvent:
    """Representa un evento de autenticación normalizado de Linux (/var/log/auth.log)."""

    line_number: int
    timestamp: str
    hostname: str
    process: str
    pid: int
    event_type: str        # FAILED_LOGIN | ACCEPTED_LOGIN
    auth_method: str       # password | publickey
    username: str
    is_invalid_user: bool  # True si el usuario no existe en el sistema ("invalid user")
    source_ip: str
    source_port: int
    raw_log: str


@dataclass
class WebAccessEvent:
    """Representa una petición HTTP normalizada de Nginx/Apache (Combined Log Format)."""

    line_number: int
    source_ip: str
    timestamp: str
    http_method: str
    uri: str
    decoded_uri: str       # URI decodificada (ej. %2F -> /) para detectar ataques ofuscados
    protocol: str
    status_code: int
    response_bytes: int
    referer: str
    user_agent: str
    raw_log: str


# Expresión regular para eventos de login SSH (Failed / Accepted) en Syslog
SSH_AUTH_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[\w\-]+)\s+"
    r"(?P<process>sshd)\[(?P<pid>\d+)\]:\s+"
    r"(?P<action>Failed|Accepted)\s+"
    r"(?P<auth_method>password|publickey)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?"
    r"(?P<username>[\w\-\.]+)\s+from\s+"
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+"
    r"(?P<source_port>\d+)"
)

# Expresión regular para Nginx / Apache Combined Log Format
WEB_ACCESS_REGEX = re.compile(
    r"^(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<http_method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status_code>\d{3})\s+"
    r"(?P<response_bytes>\d+|-)\s+"
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


def parse_ssh_auth_line(line: str, line_number: int = 0) -> Optional[SSHAuthEvent]:
    """
    Analiza una línea de /var/log/auth.log y devuelve un SSHAuthEvent si corresponde
    a un intento de autenticación SSH (exitoso o fallido).
    """
    clean_line = line.strip()
    if not clean_line:
        return None

    match = SSH_AUTH_REGEX.search(clean_line)
    if not match:
        return None

    data = match.groupdict()
    event_type = "FAILED_LOGIN" if data["action"] == "Failed" else "ACCEPTED_LOGIN"

    return SSHAuthEvent(
        line_number=line_number,
        timestamp=data["timestamp"],
        hostname=data["hostname"],
        process=data["process"],
        pid=int(data["pid"]),
        event_type=event_type,
        auth_method=data["auth_method"],
        username=data["username"],
        is_invalid_user=bool(data["invalid"]),
        source_ip=data["source_ip"],
        source_port=int(data["source_port"]),
        raw_log=clean_line,
    )


def parse_ssh_auth_file(filepath: str | Path) -> List[SSHAuthEvent]:
    """Lee un archivo auth.log completo y retorna la lista de eventos SSH normalizados."""
    events: List[SSHAuthEvent] = []
    path = Path(filepath)

    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            parsed = parse_ssh_auth_line(line, line_number=idx)
            if parsed is not None:
                events.append(parsed)

    return events


def parse_web_access_line(line: str, line_number: int = 0) -> Optional[WebAccessEvent]:
    """
    Analiza una línea de access.log (Nginx/Apache) y devuelve un WebAccessEvent
    incluyendo la URI decodificada (URL decoding) para inspección de payloads.
    """
    clean_line = line.strip()
    if not clean_line:
        return None

    match = WEB_ACCESS_REGEX.search(clean_line)
    if not match:
        return None

    data = match.groupdict()
    raw_bytes = data["response_bytes"]
    response_bytes = int(raw_bytes) if raw_bytes.isdigit() else 0

    return WebAccessEvent(
        line_number=line_number,
        source_ip=data["source_ip"],
        timestamp=data["timestamp"],
        http_method=data["http_method"],
        uri=data["uri"],
        decoded_uri=unquote(data["uri"]),
        protocol=data["protocol"],
        status_code=int(data["status_code"]),
        response_bytes=response_bytes,
        referer=data["referer"],
        user_agent=data["user_agent"],
        raw_log=clean_line,
    )


def parse_web_access_file(filepath: str | Path) -> List[WebAccessEvent]:
    """Lee un archivo access.log completo y retorna la lista de eventos HTTP normalizados."""
    events: List[WebAccessEvent] = []
    path = Path(filepath)

    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            parsed = parse_web_access_line(line, line_number=idx)
            if parsed is not None:
                events.append(parsed)

    return events
