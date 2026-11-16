"""
Vercel Serverless Function Entrypoint for Aegis AI-NIDS & Sentinel CTI.
Exports the FastAPI ASGI application for cloud deployment.
"""
import os
import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Import the FastAPI ASGI application instance
from backend.app.main import app

# Vercel's @vercel/python builder detects and routes to this ASGI `app`
