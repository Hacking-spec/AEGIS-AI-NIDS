"""
Unit tests for Threat Intelligence, MITRE ATT&CK Mapping, and OASIS STIX 2.1 Serialization.
"""
import sys
import unittest
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.intelligence.threat_intel import ThreatIntelligenceEngine
from backend.app.intelligence.mitre_mapper import MitreMapper
from backend.app.intelligence.stix_generator import Stix21Generator
from backend.app.models.schemas import AttackType, Alert, NetworkFlow, DetectionResult, SeverityLevel


class TestThreatIntelligence(unittest.TestCase):
    def setUp(self):
        self.ti = ThreatIntelligenceEngine()

    def test_known_malicious_ip_lookup(self):
        """Pre-populated malicious C2 IP should be flagged with high reputation score and actor."""
        res = self.ti.lookup_indicator("185.220.101.5")
        self.assertTrue(res.is_malicious)
        self.assertGreaterEqual(res.reputation_score, 90)
        self.assertEqual(res.threat_actor, "APT29 (Cozy Bear)")
        self.assertTrue(res.tor_exit_node)
        self.assertIn("CVE-2023-38831", res.cve_ids)

    def test_internal_rfc1918_lookup(self):
        """Internal private IPs should be recognized as clean internal network."""
        res = self.ti.lookup_indicator("192.168.1.100")
        self.assertFalse(res.is_malicious)
        self.assertEqual(res.reputation_score, 0)
        self.assertIn("Internal Subnet / RFC 1918", res.categories)

    def test_mitre_mapping_resolution(self):
        """AttackType should correctly map to MITRE ATT&CK techniques with descriptions and mitigations."""
        techniques = MitreMapper.get_techniques_for_attack(AttackType.DDOS)
        self.assertGreater(len(techniques), 0)
        tech_ids = [t.technique_id for t in techniques]
        self.assertIn("T1498", tech_ids)
        self.assertEqual(techniques[0].tactic, "Impact")
        self.assertTrue(techniques[0].url.startswith("https://attack.mitre.org/"))

    def test_stix_21_bundle_generation(self):
        """Alert should be converted into valid OASIS STIX 2.1 JSON bundle."""
        flow = NetworkFlow(src_ip="45.142.195.12", src_port=44321, dst_ip="192.168.1.100", dst_port=443)
        detection = DetectionResult(
            flow_id="test-stix-1",
            predicted_class=AttackType.C2_BEACON,
            confidence=0.96,
            is_anomaly=True,
            anomaly_score=0.88,
            signature_matches=["SIG-C2-001"],
            threat_score=94.0,
            severity=SeverityLevel.CRITICAL,
            mitre_techniques=MitreMapper.get_techniques_for_attack(AttackType.C2_BEACON),
            recommended_action="ISOLATE_HOST_AND_BLOCK_C2",
            auto_quarantined=True
        )
        alert = Alert(
            alert_id="ALT-999999",
            flow=flow,
            detection=detection,
            threat_intel=self.ti.lookup_indicator("45.142.195.12"),
            status="CONTAINED",
            quarantined=True
        )

        bundle = Stix21Generator.generate_bundle(alert)
        self.assertTrue(bundle.bundle_id.startswith("bundle--"))
        self.assertEqual(bundle.stix_json["type"], "bundle")
        self.assertGreater(bundle.objects_count, 3)

        # Check for Indicator object with STIX pattern
        types = [obj["type"] for obj in bundle.stix_json["objects"]]
        self.assertIn("identity", types)
        self.assertIn("indicator", types)
        self.assertIn("attack-pattern", types)
        self.assertIn("course-of-action", types)


if __name__ == "__main__":
    unittest.main()
