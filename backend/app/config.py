"""
Configuration settings for AI-Based NIDS & Automated Threat Intelligence System.
Supports standard local deployment as well as Vercel / Serverless cloud environments.
"""
import os
import tempfile
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Detect serverless / Vercel cloud environment where filesystem outside /tmp is read-only
IS_SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

if IS_SERVERLESS:
    TEMP_DIR = Path(tempfile.gettempdir())
    DATA_DIR = TEMP_DIR / "aegis_data"
    EXPORTS_DIR = DATA_DIR / "exports"
    THREAT_FEEDS_DIR = DATA_DIR / "threat_feeds"
    SAMPLES_DIR = DATA_DIR / "samples"
    DATABASE_PATH = DATA_DIR / "aegis_nids.db"
else:
    DATA_DIR = BASE_DIR / "data"
    EXPORTS_DIR = DATA_DIR / "exports"
    THREAT_FEEDS_DIR = DATA_DIR / "threat_feeds"
    SAMPLES_DIR = DATA_DIR / "samples"
    DATABASE_PATH = DATA_DIR / "aegis_nids.db"

MODELS_DIR = BASE_DIR / "backend" / "trained_models"

# Safely create writable directories
for directory in [DATA_DIR, THREAT_FEEDS_DIR, SAMPLES_DIR, EXPORTS_DIR]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


class Settings(BaseModel):
    PROJECT_NAME: str = "Aegis AI-NIDS & Sentinel CTI"
    VERSION: str = "2.5.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # Server settings
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = True
    
    # ML & Anomaly Detection Settings
    ANOMALY_THRESHOLD: float = 0.72  # Reconstruction error / anomaly threshold
    HIGH_SEVERITY_THRESHOLD: float = 75.0
    CRITICAL_SEVERITY_THRESHOLD: float = 90.0
    
    # Auto-defense / SOAR settings
    AUTO_QUARANTINE_ENABLED: bool = True
    AUTO_QUARANTINE_SEVERITY: str = "CRITICAL"  # Auto-quarantine CRITICAL attacks
    
    # Database
    DATABASE_PATH: Path = DATABASE_PATH
    
    # Model paths
    SUPERVISED_MODEL_PATH: Path = MODELS_DIR / "supervised_rf.pkl"
    ENCODER_MODEL_PATH: Path = MODELS_DIR / "autoencoder.pt"
    SCALER_PATH: Path = MODELS_DIR / "scaler.pkl"
    FEATURE_NAMES_PATH: Path = MODELS_DIR / "feature_names.json"


settings = Settings()
