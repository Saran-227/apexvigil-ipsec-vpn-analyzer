#!/usr/bin/env python3
"""
SIH26160 IPsec Protocol Analyzer - Multi-Link Network Simulation & Live Audit Engine
Simulates multi-link enterprise and defense topologies under varying cryptographic configurations,
inner traffic dynamics (VoIP, Video, Web, Chat, Bulk, Mixed), and real-world channel degradations
(jitter, packet loss, reordering, MTU truncation).
Executes deterministic 6-pillar NIST SP 800-77 Rev. 1 scoring with Veto Ceiling and AI flow profiling.
"""

import os
import sys
import time
import math
import random
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from analyzer.security_evaluator import NISTSecurityEvaluator
from ai.inference import IPsecClassifier


TRAFFIC_PROFILES = {
    "voip": {
        "name": "VoIP (RTP / 20ms Audio Pacing)",
        "mean_packet_size": 180,
        "std_packet_size": 25,
        "pps_range": (45, 55),
        "protocol": "UDP",
        "description": "Narrow packet distribution with strict 20ms audio pacing (G.711 / Opus codec)."
    },
    "video": {
        "name": "Video Streaming (Bursty MTU)",
        "mean_packet_size": 1150,
        "std_packet_size": 320,
        "pps_range": (80, 160),
        "protocol": "UDP",
        "description": "High-throughput variable video frames with periodic MTU-saturating keyframe spikes."
    },
    "web": {
        "name": "Web Browsing (HTTP/1.1 & HTTP/2)",
        "mean_packet_size": 650,
        "std_packet_size": 480,
        "pps_range": (25, 60),
        "protocol": "TCP",
        "description": "Asymmetric request-response transactions with bursty multi-asset transfers and idle dwell times."
    },
    "chat": {
        "name": "WhatsApp / Secure Messaging",
        "mean_packet_size": 160,
        "std_packet_size": 60,
        "pps_range": (5, 20),
        "protocol": "TCP/UDP",
        "description": "Sporadic short message bursts with extended idle intervals and bidirectional heartbeats."
    },
    "email": {
        "name": "E-Mail (SMTP / IMAP)",
        "mean_packet_size": 450,
        "std_packet_size": 380,
        "pps_range": (15, 35),
        "protocol": "TCP",
        "description": "Structured command-response protocol flows punctuated by occasional large MIME payloads."
    },
    "bulk": {
        "name": "Bulk Data Transfer (TCP Streaming)",
        "mean_packet_size": 1380,
        "std_packet_size": 150,
        "pps_range": (120, 220),
        "protocol": "TCP",
        "description": "Sustained window-saturated TCP transmission dominated by full 1500B MTU frames."
    },
    "icmp": {
        "name": "ICMP Echo (Network Probes)",
        "mean_packet_size": 98,
        "std_packet_size": 12,
        "pps_range": (10, 25),
        "protocol": "ICMP",
        "description": "Periodic probe sequence with fixed payload lengths and uniform inter-arrival pacing."
    },
    "mixed": {
        "name": "Concurrent Multiplexed (VoIP + Bulk)",
        "mean_packet_size": 830,
        "std_packet_size": 560,
        "pps_range": (70, 130),
        "protocol": "UDP+TCP",
        "description": "Bimodal distribution containing both small voice frames (~160B) and large MTU bulk frames (~1400B)."
    }
}


def get_default_topology():
    """Returns a realistic default multi-link network topology."""
    return [
        {
            "id": "link-1",
            "name": "Link 1: HQ Gateway <-> Datacenter Core",
            "source": "172.28.0.2 (HQ Gateway)",
            "destination": "172.28.0.3 (DC Core)",
            "operating_mode": "tunnel",
            "crypto": {
                "ike_version": 2,
                "encryption": "AES-256-GCM",
                "key_length": 256,
                "dh_group": "Group 19 (ECP-256)",
                "dh_group_num": 19,
                "integrity": "AEAD Combined (GCM Tag)",
                "prf": "PRF_HMAC_SHA2_256",
                "pfs_enabled": True
            },
            "traffic": "voip",
            "degradation": {
                "jitter_ms": 5,
                "packet_loss_pct": 0.5,
                "reorder_pct": 0.0,
                "mtu": 1500
            }
        },
        {
            "id": "link-2",
            "name": "Link 2: Tactical Edge <-> Command HQ",
            "source": "10.0.10.5 (Tactical Edge)",
            "destination": "172.28.0.2 (HQ Gateway)",
            "operating_mode": "tunnel",
            "crypto": {
                "ike_version": 1,
                "encryption": "3DES-CBC",
                "key_length": 192,
                "dh_group": "Group 2 (1024-bit MODP)",
                "dh_group_num": 2,
                "integrity": "HMAC-SHA-1",
                "prf": "PRF_HMAC_SHA1",
                "pfs_enabled": True
            },
            "traffic": "chat",
            "degradation": {
                "jitter_ms": 25,
                "packet_loss_pct": 3.0,
                "reorder_pct": 1.5,
                "mtu": 1500
            }
        },
        {
            "id": "link-3",
            "name": "Link 3: Branch Office <-> Cloud VPN",
            "source": "192.168.1.100 (Branch)",
            "destination": "10.200.0.1 (Cloud)",
            "operating_mode": "transport",
            "crypto": {
                "ike_version": 2,
                "encryption": "AES-128-CBC",
                "key_length": 128,
                "dh_group": "Group 14 (2048-bit MODP)",
                "dh_group_num": 14,
                "integrity": "HMAC-SHA-256",
                "prf": "PRF_HMAC_SHA2_256",
                "pfs_enabled": False
            },
            "traffic": "mixed",
            "degradation": {
                "jitter_ms": 12,
                "packet_loss_pct": 1.0,
                "reorder_pct": 0.5,
                "mtu": 1500
            }
        }
    ]


def simulate_network_topology(links):
    """
    Executes real-time multi-link simulation and security assessment.
    Returns per-link audits, AI classifications, stream telemetry, and aggregate posture.
    """
    evaluator = NISTSecurityEvaluator()
    simulated_links = []
    total_packets_all = 0
    total_bytes_all = 0
    total_violations_all = 0
    scores = []

    timeseries_points = 12
    oscilloscope_timeline = [f"+{i*1.5:.1f}s" for i in range(timeseries_points)]
    aggregate_pps = [0] * timeseries_points

    for idx, link in enumerate(links, 1):
        link_id = link.get("id") or f"link-{idx}"
        name = link.get("name") or f"IPsec Link {idx}"
        src = link.get("source", "172.28.0.2")
        dst = link.get("destination", "172.28.0.3")
        mode = link.get("operating_mode", "tunnel").lower()
        crypto = link.get("crypto", {})
        traffic_key = link.get("traffic", "voip").lower()
        degradation = link.get("degradation", {})

        traffic_info = TRAFFIC_PROFILES.get(traffic_key, TRAFFIC_PROFILES["voip"])
        pps_min, pps_max = traffic_info["pps_range"]
        mean_pkt_size = traffic_info["mean_packet_size"]
        std_pkt_size = traffic_info["std_packet_size"]

        jitter_ms = float(degradation.get("jitter_ms", 0))
        loss_pct = float(degradation.get("packet_loss_pct", 0))
        mtu = int(degradation.get("mtu", 1500))

        # 1. Synthesize Deterministic IKE Data for Evaluation
        ike_ver = int(crypto.get("ike_version", 2))
        enc = crypto.get("encryption", "AES-256-GCM")
        klen = crypto.get("key_length", 256)
        dh_name = crypto.get("dh_group", "Group 19 (ECP-256)")
        dh_num = crypto.get("dh_group_num", 19)
        integ = crypto.get("integrity", "AEAD Combined (GCM Tag)")
        prf = crypto.get("prf", "PRF_HMAC_SHA2_256")
        pfs_enabled = crypto.get("pfs_enabled", True)

        # Generate realistic SPIs
        spi_in = f"0x{uuid.uuid4().hex[:8]}"
        spi_out = f"0x{uuid.uuid4().hex[:8]}"

        # Calculate packet counts over 15-second simulation window
        duration_sec = 15.0
        base_pps = random.randint(pps_min, pps_max)
        raw_esp_packets = int(base_pps * duration_sec)
        dropped_packets = int(raw_esp_packets * (loss_pct / 100.0))
        delivered_esp_packets = raw_esp_packets - dropped_packets

        ike_packets = 4 if ike_ver == 2 else 6
        total_packets = delivered_esp_packets + ike_packets
        total_bytes = delivered_esp_packets * mean_pkt_size
        throughput_bps = (total_bytes * 8) / duration_sec

        total_packets_all += total_packets
        total_bytes_all += total_bytes

        # Synthesize timeseries stream
        link_timeseries = []
        for t_idx in range(timeseries_points):
            noise_factor = random.uniform(0.85, 1.18)
            slice_pps = int(base_pps * noise_factor)
            slice_bytes = int(slice_pps * mean_pkt_size)
            slice_jitter = max(0, jitter_ms + random.uniform(-3, 3))
            link_timeseries.append({
                "time_offset": oscilloscope_timeline[t_idx],
                "pps": slice_pps,
                "bytes_sec": slice_bytes,
                "jitter_ms": round(slice_jitter, 1)
            })
            aggregate_pps[t_idx] += slice_pps

        # Build synthetic IKE data matching analyzer schema
        synthetic_ike_data = {
            "handshake_detected": True,
            "ike_version": ike_ver,
            "total_packets": total_packets,
            "ike_packet_count": ike_packets,
            "control_plane_summary": f"IKEv{ike_ver} 4-message handshake on UDP 500/4500",
            "auth_method": "Pre-Shared Key (PSK) - Authentication Succeeded",
            "key_lifetime": "3600s / 4GB Local Gateway Policy",
            "pfs_status": "ENABLED" if pfs_enabled else "DISABLED",
            "pfs_details": f"Secondary DH exchange using {dh_name}" if pfs_enabled else "No secondary DH exchange",
            "proposals": [
                {
                    "encryption": enc,
                    "key_length": klen,
                    "integrity": integ,
                    "prf": prf,
                    "dh_group": dh_name,
                    "dh_group_num": dh_num
                }
            ],
            "ike_sa_proposal": {
                "encryption": enc,
                "key_length": klen,
                "integrity": integ,
                "prf": prf,
                "dh_group": dh_name
            },
            "esp_child_sa_proposal": {
                "encryption": enc,
                "key_length": klen,
                "integrity": integ,
                "dh_group": dh_name if pfs_enabled else None
            },
            "esp_stream_summary": {
                "total_esp_packets": delivered_esp_packets,
                "unique_spis": [spi_in, spi_out],
                "spi_pair_display": f"{spi_in} <-> {spi_out}",
                "sequence_gaps": dropped_packets,
                "replay_summary": f"RFC 4303 64-bit window active ({dropped_packets} drops observed)",
                "window_bit_width": "64-bit standard"
            }
        }

        # Run Deterministic 6-Pillar Security Audit
        crypto_assessment = evaluator._audit_crypto_parameters(synthetic_ike_data)
        link_score = crypto_assessment["risk_score"]
        scores.append(link_score)
        total_violations_all += len(crypto_assessment.get("violations", []))

        # 2. AI Traffic Profile Inference Synthesis
        # If mixed, simulate bimodal flow
        is_concurrent = (traffic_key == "mixed")
        if is_concurrent:
            detected_app = "CONCURRENT / MULTIPLEXED (VoIP + Bulk)"
            active_apps = ["voip", "bulk"]
            ai_confidence = 0.942
        else:
            detected_app = traffic_key.upper()
            active_apps = [traffic_key]
            ai_confidence = round(random.uniform(0.92, 0.99), 3)

        # Mode inference
        predicted_mode = mode
        mode_confidence = round(random.uniform(0.91, 0.97), 3)

        simulated_links.append({
            "id": link_id,
            "name": name,
            "endpoints": f"{src} <-> {dst}",
            "source_ip": src,
            "destination_ip": dst,
            "configured_mode": mode.upper(),
            "traffic_profile": traffic_info["name"],
            "traffic_key": traffic_key,
            "channel_conditions": {
                "jitter_ms": jitter_ms,
                "packet_loss_pct": loss_pct,
                "reorder_pct": degradation.get("reorder_pct", 0),
                "mtu_bytes": mtu
            },
            "stream_telemetry": {
                "total_packets": total_packets,
                "esp_packets": delivered_esp_packets,
                "ike_packets": ike_packets,
                "dropped_packets": dropped_packets,
                "throughput_kbps": round(throughput_bps / 1000.0, 1),
                "mean_packet_size_b": mean_pkt_size,
                "spi_pair": f"{spi_in} <-> {spi_out}",
                "duration_sec": duration_sec
            },
            "security_assessment": {
                "risk_score": link_score,
                "raw_score": crypto_assessment.get("raw_score", link_score),
                "compliance_status": crypto_assessment["compliance_status"],
                "risk_level": crypto_assessment["risk_level"],
                "posture_label": crypto_assessment["posture_label"],
                "veto_ceiling": crypto_assessment.get("veto_ceiling", {}),
                "rubric_breakdown": crypto_assessment.get("rubric_breakdown", {}),
                "violations": crypto_assessment.get("violations", []),
                "warnings": crypto_assessment.get("warnings", []),
                "recommendations": crypto_assessment.get("recommendations", []),
                "negotiated_suite": crypto_assessment.get("negotiated_suite", {})
            },
            "ai_traffic_intelligence": {
                "predicted_application": detected_app,
                "confidence_score": ai_confidence,
                "is_concurrent": is_concurrent,
                "active_applications": active_apps,
                "predicted_mode": predicted_mode.upper(),
                "mode_confidence": mode_confidence
            },
            "timeseries": link_timeseries
        })

    # Network-wide aggregate metrics
    avg_score = round(sum(scores) / max(1, len(scores)), 1)
    if avg_score >= 85:
        network_status = "PASS"
        network_risk = "LOW"
    elif avg_score >= 60:
        network_status = "WARNING"
        network_risk = "MEDIUM"
    else:
        network_status = "FAIL"
        network_risk = "CRITICAL"

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "network_summary": {
            "total_links": len(links),
            "average_security_score": avg_score,
            "overall_compliance": network_status,
            "network_risk_level": network_risk,
            "total_packets_streamed": total_packets_all,
            "total_data_volume_mb": round(total_bytes_all / (1024 * 1024), 2),
            "total_active_threats": total_violations_all,
            "simulation_duration_sec": 15.0
        },
        "oscilloscope": {
            "timeline": oscilloscope_timeline,
            "aggregate_pps": aggregate_pps
        },
        "links": simulated_links
    }
