"""
Direct Integration tests for FastAPI REST API endpoints.
Tests route handlers synchronously with realistic network flows and mock data.
"""
import sys
import unittest
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.main import (
    health_check, get_metrics, ingest_flow, launch_simulation,
    quarantine_host, unquarantine_host, list_quarantined_hosts,
    lookup_threat_intel, generate_firewall_rules
)
from backend.app.models.schemas import NetworkFlow, SimulationRequest, MitigationActionRequest, ProtocolType


class TestFastAPIRouteHandlers(unittest.TestCase):
    def test_health_endpoint(self):
        res = health_check()
        self.assertEqual(res["status"], "HEALTHY")
        self.assertTrue(res["models"]["supervised_ml"])
        self.assertTrue(res["models"]["autoencoder_anomaly"])

    def test_metrics_endpoint(self):
        metrics = get_metrics()
        self.assertGreaterEqual(metrics.total_flows_processed, 0)
        self.assertIn("DEFCON", metrics.active_threat_level)

    def test_flow_ingest_endpoint(self):
        flow = NetworkFlow(
            flow_id="api-test-flow-1",
            src_ip="185.220.101.5",
            src_port=34123,
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol=ProtocolType.TCP,
            service="http",
            duration=0.4,
            src_bytes=800,
            dst_bytes=1200,
            src_packets=8,
            dst_packets=10,
            flag="SF",
            payload_preview="GET /login?user=admin' OR '1'='1 HTTP/1.1"
        )
        res = ingest_flow(flow)
        self.assertEqual(res["status"], "PROCESSED")
        self.assertTrue(res["alert_triggered"])
        self.assertIsNotNone(res["alert_id"])

    def test_simulation_launch_endpoint(self):
        req = SimulationRequest(
            attack_type="ddos_syn",
            packet_count=3,
            target_ip="192.168.1.100"
        )
        res = launch_simulation(req)
        self.assertEqual(res["status"], "SIMULATION_COMPLETED")
        self.assertEqual(res["flows_generated"], 3)
        self.assertGreater(res["threats_detected"], 0)

    def test_quarantine_endpoints(self):
        ip = "194.26.29.114"
        req = MitigationActionRequest(ip=ip, reason="Test Quarantine")
        
        # 1. Quarantine
        res = quarantine_host(req)
        self.assertEqual(res["status"], "QUARANTINED")
        self.assertIn("iptables", res["generated_rules"])

        # 2. Verify in list
        list_res = list_quarantined_hosts()
        ips = [item["ip"] for item in list_res]
        self.assertIn(ip, ips)

        # 3. Unquarantine
        unq_res = unquarantine_host(req)
        self.assertEqual(unq_res["status"], "UNQUARANTINED")

    def test_threat_intel_lookup_endpoint(self):
        data = lookup_threat_intel("45.142.195.12")
        self.assertTrue(data.is_malicious)
        self.assertEqual(data.indicator, "45.142.195.12")
        self.assertIn("Cobalt Strike C2", data.categories)

    def test_generate_firewall_rules_endpoint(self):
        rules = generate_firewall_rules("103.145.13.88", 80, "tcp")
        self.assertIn("iptables", rules)
        self.assertIn("windows_netsh", rules)


if __name__ == "__main__":
    unittest.main()
