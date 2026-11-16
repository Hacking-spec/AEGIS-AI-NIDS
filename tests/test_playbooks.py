"""
Unit tests for SOAR Mitigation Playbooks & Multi-Vendor Firewall rule generation.
"""
import sys
import unittest
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.intelligence.playbook_engine import PlaybookEngine


class TestPlaybooks(unittest.TestCase):
    def test_firewall_rule_generation(self):
        ip = "194.26.29.114"
        rules = PlaybookEngine.generate_firewall_rules(ip, port=80, protocol="tcp")
        
        self.assertIn("iptables", rules)
        self.assertIn("windows_netsh", rules)
        self.assertIn("cisco_ios", rules)
        self.assertIn("aws_security_group", rules)

        self.assertIn(f"-s {ip} -j DROP", rules["iptables"])
        self.assertIn(f"remoteip={ip}", rules["windows_netsh"])
        self.assertIn(f"deny ip host {ip}", rules["cisco_ios"])
        self.assertIn(f"--cidr {ip}/32", rules["aws_security_group"])

    def test_host_isolation_scripts(self):
        host_ip = "192.168.1.112"
        scripts = PlaybookEngine.generate_host_isolation_script(host_ip)

        self.assertIn("linux_quarantine", scripts)
        self.assertIn("windows_quarantine", scripts)

        self.assertIn("iptables -A INPUT -j DROP", scripts["linux_quarantine"])
        self.assertIn("New-NetFirewallRule", scripts["windows_quarantine"])

    def test_playbook_workflow_recommendations(self):
        ddos_pb = PlaybookEngine.get_playbook_recommendation("DDoS / DoS Flood", "CRITICAL", "1.2.3.4")
        self.assertEqual(ddos_pb["recommended_action"], "QUARANTINE_IP_AND_RATE_LIMIT")
        self.assertEqual(ddos_pb["automation_level"], "AUTOMATIC")

        c2_pb = PlaybookEngine.get_playbook_recommendation("Botnet C2 Beaconing", "CRITICAL", "45.142.195.12")
        self.assertEqual(c2_pb["recommended_action"], "ISOLATE_HOST_AND_BLOCK_C2")


if __name__ == "__main__":
    unittest.main()
