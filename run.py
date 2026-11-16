"""
Aegis AI-NIDS & Sentinel CTI Launcher.
Single-command startup script for the Cyber Defense Operations Center.
"""
import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.config import settings


def banner():
    print("""
    =======================================================================
       █████╗ ███████╗ ██████╗ ██╗███████╗    ███╗   ██╗██╗██████╗ ███████╗
      ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ████╗  ██║██║██╔══██╗██╔════╝
      ███████║█████╗  ██║  ███╗██║███████╗    ██╔██╗ ██║██║██║  ██║███████╗
      ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║╚██╗██║██║██║  ██║╚════██║
      ██║  ██║███████╗╚██████╔╝██║███████║    ██║ ╚████║██║██████╔╝███████║
      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
      AI-Based Network Intrusion Detection & Automated Threat Intelligence
    =======================================================================
      [+] SOC Analyst Dashboard:  http://localhost:8000
      [+] Interactive API Docs:   http://localhost:8000/docs
      [+] WebSocket Feed:         ws://localhost:8000/ws/soc-feed
      [+] Threat Intelligence:    Integrated MITRE ATT&CK & STIX 2.1
      [+] Automated Response:     SOAR Playbooks & Multi-Vendor Firewalls
    =======================================================================
    """)


def main():
    banner()
    
    # Auto-train models if they do not exist yet
    if not settings.SUPERVISED_MODEL_PATH.exists() or not settings.ENCODER_MODEL_PATH.exists():
        print("[!] Detection models not found. Bootstrapping initial training...")
        from train_models import train_and_evaluate
        train_and_evaluate()
        print("[✓] Model bootstrapping complete.\n")

    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()
