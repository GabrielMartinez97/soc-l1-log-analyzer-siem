"""
Punto de entrada CLI para el Mini-SIEM & Log Triage Engine (SOC L1).

Uso:
    python main.py
    python main.py --ssh-log logs/linux_auth.log --web-log logs/web_access.log
"""

import argparse
from pathlib import Path
import sys

from src.detector import detect_ssh_threats, detect_web_threats
from src.parsers import parse_ssh_auth_file, parse_web_access_file
from src.reporter import (
    defang_ioc,
    generate_json_report,
    generate_markdown_report,
    sort_alerts_by_priority,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC L1 Mini-SIEM & Log Triage Engine con mapeo MITRE ATT&CK"
    )
    parser.add_argument(
        "--ssh-log",
        type=str,
        default="logs/linux_auth.log",
        help="Ruta al archivo de logs SSH de Linux (auth.log)",
    )
    parser.add_argument(
        "--web-log",
        type=str,
        default="logs/web_access.log",
        help="Ruta al archivo de logs HTTP (access.log)",
    )
    parser.add_argument(
        "--md-out",
        type=str,
        default="reports/SOC_L1_Incident_Report.md",
        help="Ruta de salida para el reporte de incidente en Markdown",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default="reports/soc_alerts.json",
        help="Ruta de salida para las alertas en formato JSON",
    )
    return parser


def main() -> int:
    # Configurar salida estándar en UTF-8 para terminales de Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_arg_parser().parse_args()

    ssh_path = Path(args.ssh_log)
    web_path = Path(args.web_log)

    print("=" * 78)
    print("  SOC L1 MINI-SIEM & LOG TRIAGE ENGINE — MITRE ATT&CK CORRELATOR")
    print("=" * 78)

    ssh_events = parse_ssh_auth_file(ssh_path) if ssh_path.exists() else []
    web_events = parse_web_access_file(web_path) if web_path.exists() else []

    print(f"[+] Eventos SSH normalizados ({ssh_path}): {len(ssh_events)}")
    print(f"[+] Eventos Web normalizados ({web_path}): {len(web_events)}")
    print("-" * 78)

    raw_alerts = detect_ssh_threats(ssh_events) + detect_web_threats(web_events)
    alerts = sort_alerts_by_priority(raw_alerts)

    print(f"[!] Total de Alertas de Seguridad Detectadas: {len(alerts)}\n")
    print(f"{'SEV':<10} | {'RULE ID':<12} | {'MITRE':<10} | {'IOC (DEFANGED)':<18} | {'TITLE'}")
    print("-" * 95)

    for alert in alerts:
        defanged = defang_ioc(alert.source_ip)
        print(
            f"{alert.severity:<10} | {alert.rule_id:<12} | {alert.mitre_technique_id:<10} | "
            f"{defanged:<18} | {alert.title}"
        )

    print("-" * 95)
    md_file = generate_markdown_report(alerts, args.md_out)
    json_file = generate_json_report(alerts, args.json_out)

    print(f"\n[OK] Reporte SOC L1 (Markdown) generado en: {md_file}")
    print(f"[OK] Exportación SOAR (JSON) generada en:   {json_file}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
