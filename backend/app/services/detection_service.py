"""
Central Intrusion Detection and Threat Intelligence Orchestration Service.
Processes incoming network flows synchronously for ultra-low latency,
and provides async WebSocket broadcasting for live SOC analyst dashboards.
"""
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from fastapi import WebSocket

from backend.app.config import settings
from backend.app.models.schemas import (
    NetworkFlow, Alert, DetectionResult, AttackType, SeverityLevel, ThreatIntelHit
)
from backend.app.models.ml_detector import MLDetector
from backend.app.models.anomaly_detector import AnomalyDetector
from backend.app.models.signature_engine import SignatureEngine
from backend.app.models.ensemble import EnsembleDetector
from backend.app.intelligence.threat_intel import ThreatIntelligenceEngine
from backend.app.intelligence.playbook_engine import PlaybookEngine
from backend.app.services.storage_service import StorageService


class DetectionService:
    def __init__(self):
        self.storage = StorageService()
        self.ml_detector = MLDetector()
        self.anomaly_detector = AnomalyDetector()
        self.signature_engine = SignatureEngine()
        self.threat_intel = ThreatIntelligenceEngine()
        
        # Load pre-trained models if they exist
        self._load_models()

        self.ensemble = EnsembleDetector(
            ml_detector=self.ml_detector,
            anomaly_detector=self.anomaly_detector,
            signature_engine=self.signature_engine
        )

        self.active_websockets: List[WebSocket] = []

    def _load_models(self):
        """Loads trained weights from disk if present."""
        if settings.SUPERVISED_MODEL_PATH.exists() and settings.SCALER_PATH.exists():
            loaded = self.ml_detector.load(settings.SUPERVISED_MODEL_PATH, settings.SCALER_PATH)
            if loaded:
                print("[✓] Supervised ML Classifier loaded successfully.")

        if settings.ENCODER_MODEL_PATH.exists():
            loaded = self.anomaly_detector.load(settings.ENCODER_MODEL_PATH)
            if loaded:
                print("[✓] Deep AutoEncoder Anomaly Detector loaded successfully.")

    async def register_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.append(websocket)

    def unregister_websocket(self, websocket: WebSocket):
        if websocket in self.active_websockets:
            self.active_websockets.remove(websocket)

    def broadcast_event(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts real-time events to all connected SOC analyst dashboards."""
        if not self.active_websockets:
            return
        payload = {"type": event_type, "data": data}
        import asyncio
        for ws in list(self.active_websockets):
            try:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(ws.send_json(payload))
                except RuntimeError:
                    pass
            except Exception:
                self.unregister_websocket(ws)

    def process_flow(self, flow: NetworkFlow) -> Tuple[Optional[Alert], Dict[str, Any]]:
        """
        Synchronous core detection pipeline for an incoming network flow.
        1. Benchmarks processing latency
        2. Executes multi-model ensemble detection
        3. Enriches flow with Threat Intelligence
        4. Generates mitigation rules
        5. Triggers automated quarantine if severity threshold met
        6. Persists alert into storage
        Returns:
            (alert, flow_event_data)
        """
        t0 = time.perf_counter()

        # Step 1: Run ensemble detection
        detection: DetectionResult = self.ensemble.evaluate_flow(flow)

        # Step 2: CTI Enrichment
        cti_hit: ThreatIntelHit = self.threat_intel.lookup_indicator(flow.src_ip)

        # Adjust score if known malicious threat intel matches
        if cti_hit.is_malicious:
            boost = (cti_hit.reputation_score / 100.0) * 15.0
            detection.threat_score = min(round(detection.threat_score + boost, 1), 100.0)
            if detection.threat_score >= 90.0:
                detection.severity = SeverityLevel.CRITICAL
                detection.auto_quarantined = True
            elif detection.threat_score >= 75.0:
                detection.severity = SeverityLevel.HIGH

        # Step 3: Record latency
        latency_ms = (time.perf_counter() - t0) * 1000.0
        self.storage.record_latency(latency_ms)

        # Step 4: Record flow
        self.storage.record_flow(flow)

        # Check if this qualifies as an Alert (Attack or high anomaly)
        is_threat = (detection.predicted_class != AttackType.BENIGN or detection.threat_score >= 25.0)

        alert = None
        if is_threat:
            alert_id = f"ALT-{int(time.time()*1000)%1000000:06d}"
            firewall_rules = PlaybookEngine.generate_firewall_rules(
                ip=flow.src_ip,
                port=flow.dst_port,
                protocol=str(flow.protocol).lower()
            )

            is_quarantined = detection.auto_quarantined and settings.AUTO_QUARANTINE_ENABLED

            alert = Alert(
                alert_id=alert_id,
                flow=flow,
                detection=detection,
                threat_intel=cti_hit,
                status="CONTAINED" if is_quarantined else "NEW",
                quarantined=is_quarantined,
                firewall_rules=firewall_rules,
                analyst_notes=f"Auto-flagged by Aegis Ensemble (Score: {detection.threat_score}/100)"
            )

            # Persist alert
            self.storage.record_alert(alert)

        flow_data = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "protocol": flow.protocol.value,
            "threat_score": detection.threat_score,
            "severity": detection.severity.value,
            "is_threat": is_threat,
            "latency_ms": round(latency_ms, 2)
        }

        return alert, flow_data


# Singleton instance
detection_service = DetectionService()
