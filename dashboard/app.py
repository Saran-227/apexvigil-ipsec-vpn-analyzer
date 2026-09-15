#!/usr/bin/env python3
"""
SIH26160 IPsec VPN Intelligence Platform - FastAPI Backend
Provides REST endpoints for deterministic IKE auditing, AI encrypted traffic classification,
tournament leaderboard metrics, and live PCAP analysis.
"""

import os
import sys
import json
import glob
import shutil
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from analyzer.security_evaluator import NISTSecurityEvaluator

app = FastAPI(
    title="NTRO IPsec Intelligence & Security Assessment Platform - API",
    description="SIH26160 Automated Cryptographic Audit & AI Encrypted Traffic Classifier (REST API)",
    version="2.0.0"
)

DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset", "raw_pcapng")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

evaluator = NISTSecurityEvaluator()


@app.get("/")
async def api_root():
    """
    Root API health and endpoint index.
    The interactive dashboard UI runs independently via React Vite on http://localhost:5173.
    """
    return {
        "service": "NTRO IPsec Intelligence Platform API",
        "version": "2.0.0",
        "status": "ONLINE",
        "interactive_docs": "/docs",
        "frontend_dashboard": "http://localhost:5173",
        "endpoints": {
            "health": "/api/health",
            "samples": "/api/samples",
            "analyze_sample": "/api/analyze/sample?id={sample_id}",
            "analyze_upload": "/api/analyze/upload",
            "tournament": "/api/tournament"
        }
    }


@app.get("/api/health")
async def health_check():
    leaderboard_file = os.path.join(MODELS_DIR, "tournament_leaderboard.json")
    champ = "HistGradientBoosting (80.50%)"
    if os.path.exists(leaderboard_file):
        try:
            with open(leaderboard_file, "r") as f:
                d = json.load(f)
                champ = f"{d.get('champion')} ({d.get('test_accuracy')*100:.1f}%)"
        except Exception:
            pass

    return {
        "status": "ONLINE",
        "system": "NTRO IPsec VPN Protocol Analyzer (SIH26160)",
        "offline_mode": True,
        "air_gapped": True,
        "active_traffic_model": champ,
        "active_mode_model": "Extra Trees (95.44%)",
        "dataset_samples_available": len(glob.glob(os.path.join(DATASET_DIR, "*.pcapng")))
    }


@app.get("/api/samples")
async def list_sample_pcaps():
    """
    Returns a curated list of sample captures covering all key scenarios.
    """
    curated = [
        {
            "id": "golden_audit",
            "title": "Golden IKEv2 VoIP (NIST SP 800-77 Full Audit)",
            "description": "AES-256-GCM, PRF_HMAC_SHA2_256, DH Group 19 (ECP-256), 557 packets, RFC 4303 verified.",
            "expected_verdict": "PASS [LOW RISK] (Score: 100/100)",
            "expected_app": "VOIP (100.0%)",
            "tag": "GOLDEN",
            "pcap": "sih26_asim_golden.pcap"
        },
        {
            "id": "secure_voip",
            "title": "Secure IKEv2 VoIP (Transport Mode)",
            "description": "AES-128-CBC, HMAC-SHA256, Diffie-Hellman Group 14. NIST SP 800-77 Transitional Baseline.",
            "expected_verdict": "WARNING [MEDIUM RISK] (Score: 83/100)",
            "expected_app": "VOIP (100.0%)",
            "tag": "SECURE",
            "pcap": "exp_002_voip_transport_aes_gcm_16_128_1789042405.pcapng"
        },
        {
            "id": "vulnerable_3des",
            "title": "Vulnerable Legacy IKEv1 3DES (Sweet32 Vulnerable)",
            "description": "3DES-CBC, SHA-1, DH Group 2. Deprecated IKEv1. Veto capped active exploit risk.",
            "expected_verdict": "FAIL [CRITICAL RISK] (Score: 25/100, Veto Capped)",
            "expected_app": "VOIP (100.0%)",
            "tag": "CRITICAL_FAIL",
            "pcap": "exp_005_voip_tunnel_3des_cbc_1789042535.pcapng"
        },
        {
            "id": "midstream_wiretap",
            "title": "Mid-Stream ESP Wiretap (Missing Handshake)",
            "description": "Wiretap attached after key exchange. ESP-only encapsulation with no IKE packets.",
            "expected_verdict": "UNVERIFIED_HANDSHAKE (Score: 50/100)",
            "expected_app": "VOIP (99.9%)",
            "tag": "WIRETAP",
            "pcap": "exp_001_voip_tunnel_aes_gcm_16_256_1789042363.pcapng"
        },
        {
            "id": "concurrent_mixed",
            "title": "Concurrent Multiplexed Flow (Chat + ICMP)",
            "description": "Interleaved concurrent multi-application streams within a single encrypted tunnel.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "MIXED (Multi-App De-muxing)",
            "tag": "CONCURRENT",
            "pcap": "exp_106_mixed_tunnel_aes_gcm_16_256_1789046857.pcapng"
        },
        {
            "id": "video_stream",
            "title": "High-Throughput Video Streaming",
            "description": "Variable frame bursts with MTU-saturating encrypted ESP payloads.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "VIDEO (99.9%)",
            "tag": "HIGH_BW",
            "pcap": "exp_016_video_tunnel_aes_gcm_16_256_1789043005.pcapng"
        },
        {
            "id": "web_browsing",
            "title": "Interactive Web Browsing",
            "description": "Bursty HTTP/1.1 transactions with variable asset sizes and idle dwell periods.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "WEB (100.0%)",
            "tag": "BURSTY",
            "pcap": "exp_031_web_tunnel_aes_gcm_16_256_1789043654.pcapng"
        }
    ]
    return curated


class SampleRequest(BaseModel):
    pcap_filename: str


@app.post("/api/analyze/sample")
async def analyze_sample(req: SampleRequest):
    pcap_path = os.path.join(DATASET_DIR, req.pcap_filename)
    if not os.path.exists(pcap_path):
        # Check if relative path provided
        if os.path.exists(req.pcap_filename):
            pcap_path = req.pcap_filename
        else:
            raise HTTPException(status_code=404, detail=f"Sample file {req.pcap_filename} not found")

    try:
        report = evaluator.evaluate_pcap(pcap_path, models_dir=MODELS_DIR)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    """
    Accepts arbitrary .pcap or .pcapng file uploads from the analyst.
    """
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    temp_fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(file.filename)[1])
    try:
        with os.fdopen(temp_fd, "wb") as f:
            shutil.copyfileobj(file.file, f)

        report = evaluator.evaluate_pcap(temp_path, models_dir=MODELS_DIR)
        report["pcap_file"] = file.filename
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.get("/api/tournament")
async def get_tournament_leaderboard():
    board_file = os.path.join(MODELS_DIR, "tournament_leaderboard.json")
    if not os.path.exists(board_file):
        raise HTTPException(status_code=404, detail="Leaderboard not found")
    with open(board_file, "r") as f:
        return json.load(f)


# ─── Multi-Link Network Simulation & Live Stream Audit Endpoints ───────────────
from analyzer.simulator import simulate_network_topology, get_default_topology, TRAFFIC_PROFILES


class SimulationRequest(BaseModel):
    links: list


@app.get("/api/simulate/presets")
async def get_simulation_presets():
    """Returns curated multi-link topology presets and supported traffic profiles."""
    return {
        "default": get_default_topology(),
        "traffic_profiles": TRAFFIC_PROFILES
    }


@app.post("/api/simulate/run")
async def run_simulation(req: SimulationRequest):
    """
    Executes real-time multi-link IPsec network simulation and security assessment.
    """
    if not req.links:
        raise HTTPException(status_code=400, detail="At least one link configuration is required")
    try:
        results = simulate_network_topology(req.links)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

