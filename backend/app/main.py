"""
FastAPI Server & RESTful API for Aegis AI-NIDS and Sentinel Threat Intelligence.
"""
import os
import json
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

from backend.app.config import settings, BASE_DIR, EXPORTS_DIR
from backend.app.models.schemas import (
    NetworkFlow, Alert, DetectionResult, MitigationActionRequest,
    SimulationRequest, SystemMetrics, StixBundleExport, ThreatIntelHit
)
from backend.app.services.detection_service import detection_service
from backend.app.intelligence.stix_generator import Stix21Generator
from backend.app.intelligence.playbook_engine import PlaybookEngine
from backend.app.intelligence.mitre_mapper import MitreMapper
from backend.app.traffic.simulator import TrafficSimulator
from backend.app.traffic.pcap_processor import PCAPProcessor


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise AI-Powered Network Intrusion Detection & Automated Threat Intelligence System",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = BASE_DIR / "frontend"


# -------------------------------------------------------------
# WebSocket Live SOC Stream
# -------------------------------------------------------------
@app.websocket("/ws/soc-feed")
async def websocket_endpoint(websocket: WebSocket):
    await detection_service.register_websocket(websocket)
    try:
        # Send initial metrics on connect
        metrics = detection_service.storage.get_metrics()
        await websocket.send_json({"type": "METRICS_UPDATE", "data": metrics.model_dump()})
        
        while True:
            # Keep-alive receive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        detection_service.unregister_websocket(websocket)
    except Exception:
        detection_service.unregister_websocket(websocket)


# -------------------------------------------------------------
# System & Health Endpoints
# -------------------------------------------------------------
@app.get(f"{settings.API_V1_PREFIX}/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "models": {
            "supervised_ml": detection_service.ml_detector.is_trained,
            "autoencoder_anomaly": detection_service.anomaly_detector.is_trained,
            "signature_rules_count": len(detection_service.signature_engine.rules)
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get(f"{settings.API_V1_PREFIX}/metrics", response_model=SystemMetrics)
def get_metrics():
    return detection_service.storage.get_metrics()


# -------------------------------------------------------------
# Flow Ingestion & PCAP Endpoints
# -------------------------------------------------------------
@app.post(f"{settings.API_V1_PREFIX}/traffic/ingest")
def ingest_flow(flow: NetworkFlow):
    """Processes a single live network flow through the AI pipeline."""
    alert, flow_data = detection_service.process_flow(flow)
    if alert:
        detection_service.broadcast_event("NEW_ALERT", alert.model_dump())
    detection_service.broadcast_event("FLOW_PROCESSED", flow_data)
    return {
        "status": "PROCESSED",
        "flow_id": flow.flow_id,
        "alert_triggered": alert is not None,
        "alert_id": alert.alert_id if alert else None
    }


@app.post(f"{settings.API_V1_PREFIX}/traffic/upload-pcap")
def upload_pcap(file: UploadFile = File(...)):
    """Uploads and analyzes a .pcap network capture file."""
    if not file.filename.endswith((".pcap", ".cap")):
        raise HTTPException(status_code=400, detail="File must be a standard .pcap binary format")

    temp_path = EXPORTS_DIR / f"upload_{int(time.time())}_{file.filename}"
    with open(temp_path, "wb") as f:
        content = file.file.read()
        f.write(content)

    flows = PCAPProcessor.parse_pcap_file(temp_path)
    alerts_created = []
    for flow in flows:
        alt, flow_data = detection_service.process_flow(flow)
        if alt:
            alerts_created.append(alt)
            detection_service.broadcast_event("NEW_ALERT", alt.model_dump())
        detection_service.broadcast_event("FLOW_PROCESSED", flow_data)

    return {
        "filename": file.filename,
        "total_flows_extracted": len(flows),
        "threats_detected": len(alerts_created),
        "alerts": [a.model_dump() for a in alerts_created[:10]]
    }


@app.get(f"{settings.API_V1_PREFIX}/traffic/export-pcap")
def export_pcap():
    """Generates and downloads a forensic .pcap binary file of captured flows."""
    alerts = detection_service.storage.get_alerts(limit=50)
    pcap_path = EXPORTS_DIR / f"aegis_forensic_{int(time.time())}.pcap"

    packet_records = []
    for a in alerts:
        packet_records.append({
            "src_ip": a.flow.src_ip,
            "dst_ip": a.flow.dst_ip,
            "src_port": a.flow.src_port,
            "dst_port": a.flow.dst_port,
            "protocol": a.flow.protocol.value,
            "payload": (a.flow.payload_preview or f"Threat: {a.detection.predicted_class.value}").encode("utf-8")
        })

    if not packet_records:
        # Generate baseline packet
        packet_records.append({
            "src_ip": "192.168.1.50", "dst_ip": "192.168.1.100",
            "src_port": 44321, "dst_port": 80, "protocol": "TCP",
            "payload": b"GET /forensic_baseline HTTP/1.1\r\n\r\n"
        })

    PCAPProcessor.create_pcap_file(pcap_path, packet_records)
    return FileResponse(pcap_path, media_type="application/vnd.tcpdump.pcap", filename=pcap_path.name)


# -------------------------------------------------------------
# Alerts & Incident Management Endpoints
# -------------------------------------------------------------
@app.get(f"{settings.API_V1_PREFIX}/alerts", response_model=List[Alert])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None
):
    return detection_service.storage.get_alerts(limit=limit, severity=severity, attack_type=attack_type)


@app.get(f"{settings.API_V1_PREFIX}/alerts/{{alert_id}}", response_model=Alert)
def get_alert(alert_id: str):
    alert = detection_service.storage.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@app.patch(f"{settings.API_V1_PREFIX}/alerts/{{alert_id}}/status")
def update_alert_status(alert_id: str, new_status: str = Query(...), notes: Optional[str] = None):
    success = detection_service.storage.update_alert_status(alert_id, new_status, notes)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found or update failed")
    return {"status": "UPDATED", "alert_id": alert_id, "new_status": new_status}


@app.get(f"{settings.API_V1_PREFIX}/alerts/{{alert_id}}/stix", response_model=StixBundleExport)
def export_alert_stix(alert_id: str):
    alert = detection_service.storage.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return Stix21Generator.generate_bundle(alert)


# -------------------------------------------------------------
# Threat Intelligence Hub (CTI) Endpoints
# -------------------------------------------------------------
@app.get(f"{settings.API_V1_PREFIX}/threat-intel/lookup/{{indicator}}", response_model=ThreatIntelHit)
def lookup_threat_intel(indicator: str):
    return detection_service.threat_intel.lookup_indicator(indicator)


@app.post(f"{settings.API_V1_PREFIX}/threat-intel/ioc")
def add_custom_ioc(indicator: str, data: dict):
    detection_service.threat_intel.add_custom_ioc(indicator, data)
    return {"status": "SUCCESS", "message": f"IOC {indicator} registered in threat database"}


@app.get(f"{settings.API_V1_PREFIX}/threat-intel/mitre-matrix")
def get_mitre_matrix():
    return MitreMapper.get_all_matrix_techniques()


# -------------------------------------------------------------
# Automated Mitigation & SOAR Endpoints
# -------------------------------------------------------------
@app.post(f"{settings.API_V1_PREFIX}/mitigation/quarantine")
def quarantine_host(req: MitigationActionRequest):
    entry = detection_service.storage.quarantine_ip(req.ip, reason=req.reason or "Manual Quarantine", severity="HIGH")
    rules = PlaybookEngine.generate_firewall_rules(req.ip)
    detection_service.broadcast_event("HOST_QUARANTINED", {"ip": req.ip, "entry": entry})
    return {"status": "QUARANTINED", "entry": entry, "generated_rules": rules}


@app.post(f"{settings.API_V1_PREFIX}/mitigation/unquarantine")
def unquarantine_host(req: MitigationActionRequest):
    success = detection_service.storage.unquarantine_ip(req.ip)
    if not success:
        raise HTTPException(status_code=404, detail=f"IP {req.ip} is not currently quarantined")
    detection_service.broadcast_event("HOST_UNQUARANTINED", {"ip": req.ip})
    return {"status": "UNQUARANTINED", "ip": req.ip}


@app.get(f"{settings.API_V1_PREFIX}/mitigation/quarantined")
def list_quarantined_hosts():
    return detection_service.storage.get_quarantined_ips()


@app.post(f"{settings.API_V1_PREFIX}/mitigation/generate-firewall-rules")
def generate_firewall_rules(ip: str, port: int = 0, protocol: str = "tcp"):
    return PlaybookEngine.generate_firewall_rules(ip=ip, port=port, protocol=protocol)


# -------------------------------------------------------------
# Simulation Studio Endpoints
# -------------------------------------------------------------
@app.post(f"{settings.API_V1_PREFIX}/simulation/launch")
def launch_simulation(req: SimulationRequest):
    """
    Generates synthetic attack or normal network flows and feeds them directly through the live AI pipeline.
    """
    flows = TrafficSimulator.generate_batch(
        attack_type=req.attack_type,
        count=req.packet_count,
        target_ip=req.target_ip
    )

    detected_alerts = []
    for flow in flows:
        alt, flow_data = detection_service.process_flow(flow)
        if alt:
            detected_alerts.append(alt)
            detection_service.broadcast_event("NEW_ALERT", alt.model_dump())
        detection_service.broadcast_event("FLOW_PROCESSED", flow_data)

    metrics = detection_service.storage.get_metrics()
    detection_service.broadcast_event("METRICS_UPDATE", metrics.model_dump())

    return {
        "status": "SIMULATION_COMPLETED",
        "attack_type": req.attack_type,
        "flows_generated": len(flows),
        "threats_detected": len(detected_alerts),
        "target_ip": req.target_ip
    }


# -------------------------------------------------------------
# Static Frontend Assets & Web Dashboard
# -------------------------------------------------------------
PUBLIC_DIR = BASE_DIR / "public"

if PUBLIC_DIR.exists():
    if (PUBLIC_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=PUBLIC_DIR / "css"), name="public_css")
    if (PUBLIC_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=PUBLIC_DIR / "js"), name="public_js")

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_index():
    candidates = [
        PUBLIC_DIR / "index.html",
        FRONTEND_DIR / "index.html",
        Path("public/index.html"),
        Path("frontend/index.html")
    ]
    for path in candidates:
        if path.exists():
            return HTMLResponse(content=path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AEGIS AI-NIDS SOC Dashboard Running</h1>", status_code=200)
