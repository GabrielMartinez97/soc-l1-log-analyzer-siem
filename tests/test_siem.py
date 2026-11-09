"""
Pruebas unitarias para el Mini-SIEM & Log Triage Engine (SOC L1).
Verifica el parsing, la decodificación de URLs, las reglas MITRE ATT&CK y el defanging.
"""

import unittest

from src.detector import detect_ssh_threats, detect_web_threats
from src.parsers import parse_ssh_auth_line, parse_web_access_line
from src.reporter import defang_ioc, sort_alerts_by_priority


class TestSOCMiniSIEM(unittest.TestCase):
    def test_ssh_failed_and_compromise_correlation(self) -> None:
        raw_lines = [
            "Nov 08 08:20:11 prod-bastion-01 sshd[1210]: Failed password for invalid user admin from 185.220.101.45 port 44101 ssh2",
            "Nov 08 08:20:13 prod-bastion-01 sshd[1212]: Failed password for root from 185.220.101.45 port 44102 ssh2",
            "Nov 08 08:20:15 prod-bastion-01 sshd[1215]: Failed password for root from 185.220.101.45 port 44103 ssh2",
            "Nov 08 08:20:17 prod-bastion-01 sshd[1218]: Failed password for backup_svc from 185.220.101.45 port 44104 ssh2",
            "Nov 08 08:20:19 prod-bastion-01 sshd[1221]: Failed password for backup_svc from 185.220.101.45 port 44105 ssh2",
            "Nov 08 08:20:28 prod-bastion-01 sshd[1235]: Accepted password for backup_svc from 185.220.101.45 port 44109 ssh2",
        ]
        events = [parse_ssh_auth_line(line, i) for i, line in enumerate(raw_lines, 1)]
        valid_events = [e for e in events if e is not None]

        alerts = detect_ssh_threats(valid_events)
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("SOC-SSH-001", rule_ids)
        self.assertIn("SOC-SSH-003", rule_ids)

    def test_web_url_decoding_and_sqli_detection(self) -> None:
        line = (
            '198.51.100.77 - - [08/Nov/2026:09:15:24 +0000] '
            '"GET /products?id=-1%20UNION%20SELECT%201,username,password_hash%20FROM%20users-- HTTP/1.1" '
            '200 12450 "-" "sqlmap/1.8.4"'
        )
        event = parse_web_access_line(line, 1)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertIn("UNION SELECT", event.decoded_uri)

        alerts = detect_web_threats([event])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SOC-WEB-002")
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].mitre_technique_id, "T1190")

    def test_defang_ioc(self) -> None:
        self.assertEqual(defang_ioc("185.220.101.45"), "185.220.101[.]45")
        self.assertEqual(
            defang_ioc("http://c2.attacker-domain.xyz/collect"),
            "hxxp://c2.attacker-domain[.]xyz/collect",
        )


if __name__ == "__main__":
    unittest.main()
