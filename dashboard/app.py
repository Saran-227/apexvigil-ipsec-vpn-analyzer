import subprocess
from fastapi.middleware.cors import CORSMiddleware
import re
import uuid
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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





# ─── Multi-Tier Report Generation Endpoints ────────────────────────────────────
from fastapi.responses import HTMLResponse
from analyzer.report_engine import (
    generate_executive_data,
    generate_assessment_data,
    generate_technical_data,
    assemble_report_html
)

REPORTS_CACHE_DIR = os.path.join(PROJECT_ROOT, "reports_generated")
os.makedirs(REPORTS_CACHE_DIR, exist_ok=True)


class ReportRequest(BaseModel):
    report_type: str = "executive"      # "executive" | "security" | "technical"
    analysis_type: str = "pcap"         # "pcap" | "live"
    scope: str = "overall"              # "overall" | link_id
    timeframe: dict = None              # {"mode": "full"} or {"mode": "window", "start_sec": 5, "end_sec": 15}
    pcap_filename: str = None
    data: dict = None                   # evaluation or live simulation payload


@app.post("/api/reports/generate")
async def generate_report_endpoint(req: ReportRequest):
    """
    Generates an official ApexVigil intelligence report (Executive, Security Assessment, or Technical)
    for either forensic PCAP captures (full duration) or real-time multi-link streams (overall/link, full/window).
    """
    try:
        import importlib
        import analyzer.report_engine
        importlib.reload(analyzer.report_engine)
        from analyzer.report_engine import (
            generate_executive_data,
            generate_assessment_data,
            generate_technical_data,
            assemble_report_html
        )
        report_type = req.report_type.lower()
        if report_type not in ["executive", "security", "technical"]:
            report_type = "executive"

        analysis_type = req.analysis_type.lower()
        eval_data = req.data

        if analysis_type == "pcap":
            if not eval_data:
                filename = req.pcap_filename or "sih26_asim_golden.pcap"
                pcap_path = os.path.join(DATASET_DIR, filename)
                if not os.path.exists(pcap_path):
                    alt_path = os.path.join(PROJECT_ROOT, "dataset", filename)
                    if os.path.exists(alt_path):
                        pcap_path = alt_path
                    else:
                        raise HTTPException(status_code=404, detail=f"PCAP file {filename} not found")
                eval_data = evaluator.evaluate_pcap(pcap_path, models_dir=MODELS_DIR)

            if report_type == "executive":
                report_data = generate_executive_data(eval_data, source_type="pcap")
            elif report_type == "security":
                report_data = generate_assessment_data(eval_data, source_type="pcap")
            else:
                report_data = generate_technical_data(eval_data, source_type="pcap")

        else: # Live simulation
            if not eval_data or "links" not in eval_data:
                from analyzer.simulator import get_default_topology, simulate_network_topology
                eval_data = simulate_network_topology(get_default_topology())

            scope = req.scope or "overall"
            timeframe = req.timeframe or {"mode": "full"}

            if report_type == "executive":
                report_data = generate_executive_data(eval_data, source_type="live", scope=scope, timeframe=timeframe)
            elif report_type == "security":
                report_data = generate_assessment_data(eval_data, source_type="live", scope=scope, timeframe=timeframe)
            else:
                report_data = generate_technical_data(eval_data, source_type="live", scope=scope, timeframe=timeframe)

        # Assemble self-contained HTML
        html_content = assemble_report_html(report_type, report_data)
        report_id = report_data.get("meta", {}).get("id", f"AV-{uuid.uuid4().hex[:6]}")
        clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report_id)

        file_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.html")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        pdf_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.pdf")
        render_html_to_pdf(file_path, pdf_path)

        has_pdf = os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 1000
        return {
            "status": "success",
            "report_id": clean_id,
            "report_type": report_type,
            "filename": f"ApexVigil_{report_type.capitalize()}_Report.html",
            "pdf_filename": f"ApexVigil_{report_type.capitalize()}_Report.pdf",
            "view_url": f"/api/reports/view/{clean_id}",
            "pdf_url": f"/api/reports/pdf/{clean_id}",
            "pdf_download_url": f"/api/reports/pdf/download/{clean_id}",
            "download_url": f"/api/reports/download/{clean_id}",
            "has_pdf": has_pdf,
            "meta": report_data.get("meta", {})
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report generation error: {str(e)}")


@app.get("/api/reports/view/{report_id}")
async def view_report(report_id: str):
    """Renders standalone report directly in browser/Electron window."""
    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report_id)
    file_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found or expired")
    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, media_type="text/html")


@app.get("/api/reports/download/{report_id}")
async def download_report(report_id: str):
    """Downloads standalone HTML report file."""
    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report_id)
    file_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found or expired")
    return FileResponse(
        file_path,
        filename=f"ApexVigil_{clean_id}.html",
        media_type="text/html"
    )




EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

def render_html_to_pdf(html_path, pdf_path):
    """Converts HTML report to standalone PDF using headless Microsoft Edge."""
    if os.path.exists(EDGE_PATH):
        try:
            cmd = [
                EDGE_PATH,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                f"file:///{html_path}"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            return os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 1000
        except Exception as e:
            print(f"[PDF Engine] Edge headless PDF conversion error: {e}")
    return False


@app.get("/api/reports/pdf/{report_id}")
async def view_report_pdf(report_id: str):
    """Renders generated report directly as a binary PDF in browser/Electron window."""
    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report_id)
    pdf_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.pdf")
    html_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.html")

    if not os.path.exists(pdf_path):
        if not os.path.exists(html_path):
            raise HTTPException(status_code=404, detail="Report not found or expired")
        success = render_html_to_pdf(html_path, pdf_path)
        if not success or not os.path.exists(pdf_path):
            # Fallback to HTML if PDF engine is unavailable
            with open(html_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read(), media_type="text/html")

    return FileResponse(
        pdf_path,
        filename=f"ApexVigil_{clean_id}.pdf",
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=ApexVigil_{clean_id}.pdf"}
    )


@app.get("/api/reports/pdf/download/{report_id}")
async def download_report_pdf(report_id: str):
    """Triggers download of the generated PDF file."""
    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report_id)
    pdf_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.pdf")
    html_path = os.path.join(REPORTS_CACHE_DIR, f"{clean_id}.html")

    if not os.path.exists(pdf_path):
        if not os.path.exists(html_path):
            raise HTTPException(status_code=404, detail="Report not found or expired")
        success = render_html_to_pdf(html_path, pdf_path)
        if not success or not os.path.exists(pdf_path):
            raise HTTPException(status_code=500, detail="PDF generation failed")

    return FileResponse(
        pdf_path,
        filename=f"ApexVigil_{clean_id}.pdf",
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ApexVigil_{clean_id}.pdf"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

