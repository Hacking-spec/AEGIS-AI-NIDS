"""
Unit tests for Machine Learning & Deep Anomaly Intrusion Detection models.
"""
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.models.schemas import NetworkFlow, AttackType, ProtocolType
from backend.app.models.ml_detector import MLDetector
from backend.app.models.anomaly_detector import AnomalyDetector
from backend.app.models.signature_engine import SignatureEngine
from backend.app.models.ensemble import EnsembleDetector
from backend.app.config import settings


class TestMLDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ml_detector = MLDetector()
        cls.ml_detector.load(settings.SUPERVISED_MODEL_PATH, settings.SCALER_PATH)

        cls.anomaly_detector = AnomalyDetector()
        cls.anomaly_detector.load(settings.ENCODER_MODEL_PATH)

        cls.signature_engine = SignatureEngine()
        cls.ensemble = EnsembleDetector(cls.ml_detector, cls.anomaly_detector, cls.signature_engine)

    def test_benign_flow_classification(self):
        """Normal traffic should be classified as BENIGN with a low threat score."""
        benign_flow = NetworkFlow(
            flow_id="test-benign-1",
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="142.250.190.46",
            dst_port=443,
            protocol=ProtocolType.TCP,
            service="https",
            duration=0.5,
            src_bytes=1200,
            dst_bytes=5400,
            src_packets=8,
            dst_packets=12,
            flag="SF",
            serror_rate=0.01,
            rerror_rate=0.01,
            same_srv_rate=0.95,
            diff_srv_rate=0.05,
            dst_host_count=8,
            dst_host_srv_count=8,
            dst_host_same_srv_rate=0.95,
            payload_preview="GET /index.html HTTP/1.1\r\nHost: example.com"
        )
        res = self.ensemble.evaluate_flow(benign_flow)
        self.assertEqual(res.predicted_class, AttackType.BENIGN)
        self.assertLess(res.threat_score, 35.0)
        self.assertFalse(res.auto_quarantined)

    def test_ddos_syn_flood_detection(self):
        """SYN flood flow should trigger high threat score and DDoS classification."""
        ddos_flow = NetworkFlow(
            flow_id="test-ddos-1",
            src_ip="194.26.29.114",
            src_port=48921,
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol=ProtocolType.TCP,
            service="http",
            duration=0.02,
            src_bytes=64,
            dst_bytes=0,
            src_packets=650,
            dst_packets=0,
            flag="S0",
            serror_rate=0.98,
            rerror_rate=0.0,
            same_srv_rate=1.0,
            diff_srv_rate=0.0,
            dst_host_count=100,
            dst_host_srv_count=100,
            dst_host_same_srv_rate=1.0,
            payload_preview="TCP SYN Flood Packet Stream (No ACK)"
        )
        res = self.ensemble.evaluate_flow(ddos_flow)
        self.assertEqual(res.predicted_class, AttackType.DDOS)
        self.assertGreaterEqual(res.threat_score, 80.0)
        self.assertTrue(res.auto_quarantined or res.severity.value in ["HIGH", "CRITICAL"])

    def test_port_scan_detection(self):
        """Multi-service probe should trigger PORT_SCAN classification."""
        scan_flow = NetworkFlow(
            flow_id="test-scan-1",
            src_ip="103.145.13.88",
            src_port=55123,
            dst_ip="192.168.1.100",
            dst_port=445,
            protocol=ProtocolType.TCP,
            service="port_445",
            duration=0.05,
            src_bytes=52,
            dst_bytes=0,
            src_packets=2,
            dst_packets=0,
            flag="REJ",
            serror_rate=0.2,
            rerror_rate=0.85,
            same_srv_rate=0.05,
            diff_srv_rate=0.95,
            dst_host_count=85,
            dst_host_srv_count=2,
            dst_host_same_srv_rate=0.02,
            payload_preview="Nmap Scripting Engine Probe / Stealth SYN Scan"
        )
        res = self.ensemble.evaluate_flow(scan_flow)
        self.assertEqual(res.predicted_class, AttackType.PORT_SCAN)
        self.assertGreaterEqual(res.threat_score, 50.0)

    def test_sql_injection_signature_detection(self):
        """SQL injection in payload should trigger signature engine and high threat score."""
        sqli_flow = NetworkFlow(
            flow_id="test-sqli-1",
            src_ip="185.220.101.5",
            src_port=33100,
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol=ProtocolType.TCP,
            service="http",
            duration=0.3,
            src_bytes=420,
            dst_bytes=1100,
            src_packets=7,
            dst_packets=6,
            flag="SF",
            payload_preview="GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: target"
        )
        res = self.ensemble.evaluate_flow(sqli_flow)
        self.assertGreater(len(res.signature_matches), 0)
        self.assertGreaterEqual(res.threat_score, 75.0)

    def test_autoencoder_zero_day_detection(self):
        """Radical feature anomalies should yield high reconstruction error and anomaly score."""
        normal_vec = self.ml_detector.extract_features(
            NetworkFlow(src_ip="10.0.0.1", src_port=1234, dst_ip="10.0.0.2", dst_port=80)
        )
        scaled_normal = self.ml_detector.scaler.transform(normal_vec.reshape(1, -1))
        norm_res = self.anomaly_detector.predict(scaled_normal)
        self.assertFalse(norm_res["is_anomaly"])

        # Create massive synthetic outlier
        anom_scaled = scaled_normal.copy()
        anom_scaled[0, 1] += 40.0  # src_bytes
        anom_scaled[0, 12] += 80.0  # packet_rate
        anom_res = self.anomaly_detector.predict(anom_scaled)
        self.assertTrue(anom_res["is_anomaly"])
        self.assertGreater(anom_res["anomaly_score"], 0.65)


if __name__ == "__main__":
    unittest.main()
