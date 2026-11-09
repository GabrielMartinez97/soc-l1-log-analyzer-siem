"""
Módulo de Enriquecimiento Seguro (Defanging) y Generación de Reportes SOC L1.

Implementa las mejores prácticas de documentación de incidentes para escalado a SOC Nivel 2:
1. Defanging de IOCs (IPs y URLs) para evitar clics accidentales o previsualizaciones automáticas.
2. Priorización automática por severidad (CRITICAL -> HIGH -> MEDIUM -> LOW).
3. Generación de reporte ejecutivo y técnico en Markdown y exportación estructurada en JSON.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Dict, List

from src.detector import SecurityAlert

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

SEVERITY_BADGE: Dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
}


def defang_ioc(ioc: str) -> str:
    """
    Aplica 'defanging' a una dirección IP, dominio o URL maliciosa para que sea
    segura de compartir en tickets SOC (Jira, TheHive, ServiceNow) o correos.

    Ejemplos:
        '185.220.101.45' -> '185.220.101[.]45'
        'http://c2.attacker-domain.xyz/collect' -> 'hxxp://c2.attacker-domain[.]xyz/collect'
    """
    defanged = re.sub(r"^http://", "hxxp://", ioc, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)

    # Si es una IPv4 estándar, reemplazar el último punto por [.]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", defanged):
        parts = defanged.rsplit(".", 1)
        return f"{parts[0]}[.]{parts[1]}"

    # Para URLs o dominios, reemplazar el último punto del host
    return re.sub(r"\.([a-zA-Z]{2,})(/|$)", r"[.]\1\2", defanged)


def sort_alerts_by_priority(alerts: List[SecurityAlert]) -> List[SecurityAlert]:
    """Ordena las alertas desde CRITICAL hasta LOW para priorizar el triaje."""
    return sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 99))


def generate_markdown_report(alerts: List[SecurityAlert], output_path: str | Path) -> Path:
    """
    Genera un Reporte de Triaje de Incidentes SOC L1 en formato Markdown,
    listo para ser adjuntado a un ticket de escalado Nivel 2.
    """
    prioritized = sort_alerts_by_priority(alerts)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    ioc_summary: Dict[str, Dict[str, object]] = {}

    for alert in prioritized:
        counts[alert.severity] = counts.get(alert.severity, 0) + 1
        ip = alert.source_ip
        if ip not in ioc_summary:
            ioc_summary[ip] = {
                "defanged_ip": defang_ioc(ip),
                "alert_count": 0,
                "max_severity": alert.severity,
                "techniques": set(),
            }
        ioc_summary[ip]["alert_count"] = int(ioc_summary[ip]["alert_count"]) + 1
        ioc_summary[ip]["techniques"].add(alert.mitre_technique_id)  # type: ignore[union-attr]

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        "# 🚨 Reporte de Triaje de Incidentes — SOC Nivel 1",
        "",
        f"**Fecha de Generación:** `{now_str}`  ",
        "**Analista SOC L1:** Gabriel Martínez (`@GabrielMartinez97`)  ",
        f"**Total de Alertas Detectadas:** `{len(prioritized)}`  ",
        "**Estado del Ticket:** `ESCALADO A SOC NIVEL 2 (INCIDENT RESPONSE)`",
        "",
        "---",
        "",
        "## 📊 1. Resumen Ejecutivo por Severidad",
        "",
        "| Severidad | Cantidad de Alertas | SLA de Respuesta Sugerido |",
        "| :--- | :---: | :--- |",
        f"| 🔴 **CRITICAL** | **{counts['CRITICAL']}** | Inmediato (< 15 min) — Escalado a SOC L2 |",
        f"| 🟠 **HIGH** | **{counts['HIGH']}** | Urgente (< 1 hora) — Bloqueo y validación |",
        f"| 🟡 **MEDIUM** | **{counts['MEDIUM']}** | Estándar (< 4 horas) — Monitoreo y regla WAF/Firewall |",
        f"| 🔵 **LOW** | **{counts['LOW']}** | Informativo (< 24 horas) |",
        "",
        "---",
        "",
        "## 🛡️ 2. Indicadores de Compromiso (IOCs Defanged)",
        "",
        "> **Nota de Seguridad:** Todas las direcciones IP han sido neutralizadas (*defanged*) con `[.]` para prevenir conexiones accidentales durante el análisis.",
        "",
        "| IP Atacante (Defanged) | Severidad Máxima | Alertas Asociadas | Técnicas MITRE ATT&CK |",
        "| :--- | :---: | :---: | :--- |",
    ]

    for ip, info in ioc_summary.items():
        sev_label = SEVERITY_BADGE.get(str(info["max_severity"]), str(info["max_severity"]))
        techs = ", ".join(sorted(info["techniques"]))  # type: ignore[arg-type]
        lines.append(
            f"| `{info['defanged_ip']}` | {sev_label} | {info['alert_count']} | `{techs}` |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 🔍 3. Detalle Técnico de Alertas Priorizadas (Triage Log)",
        "",
    ])

    for idx, alert in enumerate(prioritized, start=1):
        badge = SEVERITY_BADGE.get(alert.severity, alert.severity)
        defanged_ip = defang_ioc(alert.source_ip)
        lines.extend([
            f"### {idx}. [{badge}] `{alert.rule_id}` — {alert.title}",
            "",
            f"- **Táctica MITRE ATT&CK:** {alert.mitre_tactic}",
            f"- **Técnica MITRE ATT&CK:** `{alert.mitre_technique_id}` ({alert.mitre_technique_name})",
            f"- **IP de Origen (Defanged):** `{defanged_ip}`",
            f"- **Activo / URI Objetivo:** `{alert.target_Asset_or_uri}`",
            f"- **Resultado del Evento:** `{alert.outcome}`",
            f"- **Análisis del Analista L1:** {alert.description}",
            f"- **Acción Recomendada / Playbook:** **{alert.recommended_action}**",
            "",
            "**Evidencia Forense (Raw Logs):**",
            "```text",
        ])
        lines.extend(alert.evidence_logs)
        lines.extend([
            "```",
            "",
        ])

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def generate_json_report(alerts: List[SecurityAlert], output_path: str | Path) -> Path:
    """Exporta las alertas priorizadas en formato JSON para integración con SIEM/SOAR."""
    prioritized = sort_alerts_by_priority(alerts)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst": "GabrielMartinez97",
        "total_alerts": len(prioritized),
        "alerts": [
            {
                **asdict(alert),
                "defanged_source_ip": defang_ioc(alert.source_ip),
            }
            for alert in prioritized
        ],
    }

    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
