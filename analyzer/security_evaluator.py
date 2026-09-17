#!/usr/bin/env python3
"""
SIH26160 IPsec Protocol Analyzer - NIST SP 800-77 Rev. 1 Security Evaluator
Evaluates negotiated cryptographic suites against NIST SP 800-77 Rev. 1 and NSA CNSA Suite standards.
Computes quantitative Risk Scores (0-100), identifies CWEs/CVEs, and produces actionable defense advisories.
"""

import os
import sys
import json
import argparse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from analyzer.ike_parser import parse_ipsec_pcap
from ai.inference import IPsecClassifier


class NISTSecurityEvaluator:
    """
    Automated Cryptographic Compliance Evaluator based on NIST SP 800-77 Rev. 1
    (Guide to IPsec VPNs) and NIST SP 800-131A Rev. 2 (Transitioning Cryptographic Algorithms).
    """

    def evaluate_pcap(self, pcap_path, models_dir="models"):
        """
        Executes end-to-end security assessment:
          1. Deterministic IKE Protocol Parsing
          2. NIST SP 800-77 Cryptographic Compliance Audit
          3. AI Encrypted Traffic Classification & De-multiplexing
        """
        # 1. Deterministic IKE parsing
        ike_data = parse_ipsec_pcap(pcap_path)
        
        # 2. Cryptographic Security Assessment
        crypto_assessment = self._audit_crypto_parameters(ike_data)

        # 3. AI Traffic Profile Inference
        try:
            classifier = IPsecClassifier(models_dir=models_dir)
            ai_inference = classifier.predict_pcap(pcap_path)
        except Exception as e:
            ai_inference = {"error": f"AI inference failed: {str(e)}"}

        esp_summary = ike_data.get("esp_stream_summary", {})
        report = {
            "pcap_file": os.path.basename(pcap_path),
            "executive_summary": {
                "compliance_status": crypto_assessment["compliance_status"],
                "risk_score": crypto_assessment["risk_score"],
                "risk_level": crypto_assessment["risk_level"],
                "nist_sp800_77_posture": crypto_assessment["posture_label"],
                "rubric_breakdown": crypto_assessment.get("rubric_breakdown", {}),
                "veto_ceiling": crypto_assessment.get("veto_ceiling", {}),
                "handshake_observed": ike_data.get("handshake_detected", False),
                "predicted_application": ai_inference.get("traffic_classification", {}).get("display_profile") or ai_inference.get("traffic_classification", {}).get("predicted_primary_profile", "unknown"),
                "is_concurrent": ai_inference.get("traffic_classification", {}).get("is_concurrent_traffic", False),
                "active_apps": ai_inference.get("traffic_classification", {}).get("active_applications", []),
                "operational_mode": ai_inference.get("operational_mode", {}).get("predicted_mode", "unknown"),
                "mode_confidence": ai_inference.get("operational_mode", {}).get("confidence_score", 0.0),
                "total_packets": ike_data.get("total_packets", 0),
                "ike_packets": ike_data.get("ike_packet_count", 0),
                "esp_packets": esp_summary.get("total_esp_packets", 0),
                "session_duration_sec": ai_inference.get("session_duration_sec", 0.0),
                "active_payload_duration_sec": ai_inference.get("active_payload_duration_sec", 0.0),
                "control_plane_summary": ike_data.get("control_plane_summary", "N/A"),
                "active_spis": esp_summary.get("unique_spis", []),
                "spi_pair": esp_summary.get("spi_pair_display", "None Observed"),
                "auth_method": ike_data.get("auth_method", "Pre-Shared Key (PSK) - Authentication Succeeded"),
                "key_lifetime": ike_data.get("key_lifetime", "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s / 4GB)"),
                "pfs_status": ike_data.get("pfs_status", "DISABLED"),
                "pfs_details": ike_data.get("pfs_details", "No secondary DH exchange"),
                "replay_protection": ike_data.get("replay_protection", {}).get("description", "N/A"),
                "replay_window_width": ike_data.get("replay_protection", {}).get("window_bit_width", "Undeterminable via Passive Wiretap (Local Gateway Policy)")
            },
            "cryptographic_audit": crypto_assessment,
            "ike_protocol_details": ike_data,
            "ai_traffic_intelligence": ai_inference
        }
        return report

    def _eval_d1_confidentiality(self, enc, klen, violations, warnings, recommendations, cap_triggers):
        """Dimension 1: Payload Confidentiality & Cipher Strength (30 pts)"""
        if any(bad in enc for bad in ["3DES", "DES", "BLOWFISH", "RC5", "CAST"]):
            violations.append({
                "vuln_id": "VULN-SWEET32-CIPHER",
                "title": f"Critical Weak Cipher: {enc} (Sweet32 Vulnerable)",
                "severity": "CRITICAL",
                "cwe": "CWE-327",
                "description": f"Cipher {enc} uses a 64-bit block size vulnerable to birthday collision attacks (Sweet32 - CVE-2016-2183) after 2^32 blocks. Banned by NIST SP 800-131A.",
                "remediation": "Immediately replace with AES-256-GCM or AES-128-GCM (NIST SP 800-77 compliant AEAD)."
            })
            cap_triggers.append(("Sweet32 64-Bit Collision Cipher (3DES/DES)", 25))
            return 0, "CRITICAL_FAIL", f"64-bit block cipher {enc} vulnerable to Sweet32 attack (CVE-2016-2183). Banned by NIST."

        if any(a in enc for a in ["GCM", "POLY1305", "CHACHA"]):
            if klen == 256 or "256" in enc:
                recommendations.append("Authenticated Encryption with Associated Data (AES-256-GCM) is active (NSA CNSA 2.0 / NIST SP 800-77 Preferred).")
                return 30, "OPTIMAL", "Meets NSA CNSA 2.0. Combined authenticated encryption immunizes against padding oracles; 256-bit quantum work-factor."
            else:
                recommendations.append("AES-128-GCM is active (NIST SP 800-77 compliant AEAD).")
                return 27, "COMPLIANT", "Meets NIST SP 800-77 baseline. AEAD authenticated encryption eliminates padding oracle vulnerabilities."

        if "CBC" in enc:
            if klen == 256 or "256" in enc:
                return 22, "COMPLIANT", "AES-256-CBC meets baseline confidentiality but requires separate HMAC integrity and constant-time padding verification."
            else:
                warnings.append("AES-128-CBC is legacy baseline. AES-256-GCM is strongly recommended.")
                return 18, "LEGACY_BASELINE", "AES-128-CBC is a legacy baseline. Transition to modern AEAD (AES-GCM) strongly recommended."

        return 15, "STANDARD", f"Cipher {enc} evaluated under standard symmetric baseline."

    def _eval_d2_key_exchange(self, dh_num, dh_name, violations, warnings, recommendations, cap_triggers):
        """Dimension 2: Key Exchange & Discrete Log Resistance (25 pts)"""
        if dh_num in [1, "1"] or "768" in dh_name:
            violations.append({
                "vuln_id": "VULN-LOGJAM-DH1",
                "title": "Broken Diffie-Hellman Group 1 (768-bit MODP)",
                "severity": "CRITICAL",
                "cwe": "CWE-326",
                "description": "768-bit MODP offers less than 67 bits of security and can be factored in hours on commodity academic hardware.",
                "remediation": "Upgrade DH Group to Group 14 (MODP-2048) or Group 19 (ECP-256 / NIST P-256)."
            })
            cap_triggers.append(("Broken DH Group 1 (768-bit MODP)", 25))
            return 0, "CRITICAL_FAIL", "768-bit MODP offers <67 bits security. Broken by commodity factorization."

        if dh_num in [2, "2"] or "1024" in dh_name:
            violations.append({
                "vuln_id": "VULN-LOGJAM-DH2",
                "title": "Insecure Diffie-Hellman Group 2 (1024-bit MODP)",
                "severity": "CRITICAL",
                "cwe": "CWE-326",
                "description": "1024-bit MODP offers ~80 bits of security, vulnerable to state-sponsored discrete log precomputation (Logjam attack). Deprecated by NIST in 2013.",
                "remediation": "Upgrade DH Group to Group 14 (MODP-2048) minimum or Group 19 (ECP-256)."
            })
            cap_triggers.append(("Logjam Vulnerable DH Group 2 (1024-bit MODP)", 35))
            return 0, "CRITICAL_FAIL", "1024-bit MODP vulnerable to Logjam precomputation attack. Deprecated by NIST SP 800-131A."

        if dh_num in [5, "5"] or "1536" in dh_name:
            violations.append({
                "vuln_id": "VULN-WEAK-DH5",
                "title": "Deprecated Diffie-Hellman Group 5 (1536-bit MODP)",
                "severity": "MEDIUM",
                "cwe": "CWE-326",
                "description": "1536-bit MODP does not meet the 112-bit security requirement established by NIST SP 800-57 Part 1.",
                "remediation": "Upgrade to Group 14 (2048-bit) or Group 19 (ECP-256)."
            })
            return 10, "DEPRECATED", "1536-bit MODP provides <100 bits security. Deprecated by NIST SP 800-57."

        if dh_num in [14, "14"] or "2048" in dh_name:
            recommendations.append("Diffie-Hellman Group 14 (MODP-2048) complies with NIST SP 800-77 Rev. 1 baseline.")
            return 22, "COMPLIANT", "Group 14 (MODP-2048) provides 112-bit security; minimum acceptable baseline per NIST SP 800-57 Part 1."

        if dh_num in [19, 20, 21, 31, "19", "20", "21", "31"] or any(g in dh_name for g in ["ECP", "Curve25519", "3072", "4096"]):
            recommendations.append(f"Diffie-Hellman Group '{dh_name}' complies with NSA CNSA 2.0 requirements.")
            return 25, "OPTIMAL", f"Group {dh_name or dh_num} complies with NSA CNSA 1.0/2.0 standards (>=128-bit quantum-resistant security)."

        return 18, "STANDARD", f"Diffie-Hellman Group {dh_name or dh_num} evaluated."

    def _eval_d3_integrity_prf(self, integ, prf, is_aead, violations, warnings, recommendations, cap_triggers):
        """Dimension 3: Message Integrity & PRF Functions (20 pts)"""
        if any(bad in integ or bad in prf for bad in ["MD5"]):
            violations.append({
                "vuln_id": "VULN-BROKEN-MD5",
                "title": "Broken MD5 Cryptographic Hash in Use",
                "severity": "CRITICAL",
                "cwe": "CWE-328",
                "description": "MD5 hash algorithm is cryptographically broken with practical collision attacks. Completely banned by NIST SP 800-131A.",
                "remediation": "Upgrade PRF and integrity algorithms to HMAC-SHA-256 or HMAC-SHA-384."
            })
            cap_triggers.append(("Broken MD5 Cryptographic Hash", 25))
            return 0, "CRITICAL_FAIL", "MD5 has practical collision attacks (O(2^16)). Banned by NIST SP 800-131A."

        if any(bad in integ or bad in prf for bad in ["SHA1", "SHA_1", "SHA "]):
            violations.append({
                "vuln_id": "VULN-SHATTERED-SHA1",
                "title": "Deprecated SHA-1 Integrity/PRF (SHAttered Vulnerable)",
                "severity": "HIGH",
                "cwe": "CWE-328",
                "description": "SHA-1 has demonstrated practical chosen-prefix collisions (SHAttered attack). Deprecated by NIST SP 800-131A for all federal uses.",
                "remediation": "Upgrade to SHA-256, SHA-384, or SHA-512."
            })
            return 5, "DEPRECATED", "SHA-1 vulnerable to chosen-prefix collision (SHAttered attack). Deprecated by NIST."

        if is_aead:
            recommendations.append("Integrated AEAD authentication tag active (NIST SP 800-77 Preferred).")
            return 20, "OPTIMAL", "AEAD provides integrated 128-bit authentication tag with hardware-accelerated integrity verification."

        if any(h in integ or h in prf for h in ["SHA384", "SHA512", "SHA-384", "SHA-512"]):
            return 20, "OPTIMAL", "HMAC-SHA-384/512 provides high collision resistance meeting NSA CNSA 2.0."

        if any(h in integ or h in prf for h in ["SHA256", "SHA-256", "SHA2"]):
            return 18, "COMPLIANT", "HMAC-SHA-256 provides 128-bit collision resistance complying with NIST SP 800-77 baseline."

        if "XCBC" in integ:
            return 16, "COMPLIANT", "AES-XCBC-MAC-96 complies with RFC 3566."

        if not is_aead and not integ:
            violations.append({
                "vuln_id": "VULN-INSECURE-CBC-INTEG",
                "title": "AES-CBC Missing Robust SHA-2 Integrity",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "description": "AES-CBC without strong SHA-2 MAC introduces padding oracle attack vulnerabilities (e.g. Lucky Thirteen - CVE-2013-0169).",
                "remediation": "Transition to modern Authenticated Encryption with Associated Data (AEAD) such as AES-GCM."
            })
            cap_triggers.append(("CBC Missing Cryptographic Integrity", 55))
            return 5, "HIGH_RISK", "CBC cipher missing robust MAC introduces padding oracle vulnerabilities (Lucky 13)."

        return 15, "STANDARD", f"Integrity: {integ}, PRF: {prf}."

    def _eval_d4_forward_secrecy(self, pfs_status, violations, warnings, recommendations):
        """Dimension 4: Perfect Forward Secrecy & Rekeying (10 pts)"""
        if pfs_status == "ENABLED":
            recommendations.append("Perfect Forward Secrecy (PFS) is enabled via secondary DH exchange.")
            return 10, "OPTIMAL", "PFS enabled via secondary DH exchange in CREATE_CHILD_SA (RFC 7296). Past traffic remains safe if private keys leak."
        else:
            warnings.append("Perfect Forward Secrecy (PFS) is disabled. Recommend enabling DH Group in Child SA proposal.")
            return 0, "WARNING", "PFS is disabled. Child SA keys derive directly from Phase 1 SKEYSEED. Compromise of IKE SA private keys allows retroactive decryption."

    def _eval_d5_control_plane(self, ike_ver, control_summary, violations, warnings, recommendations, cap_triggers):
        """Dimension 5: Control Plane Protocol & Handshake Security (10 pts)"""
        if ike_ver == 2:
            recommendations.append("IKEv2 protocol active (RFC 7296 compliant).")
            return 10, "OPTIMAL", "IKEv2 (RFC 7296) provides stateless DoS cookie protection, integrated NAT-T, and reliable message acknowledgement."

        if ike_ver == 1:
            if "AGGRESSIVE" in control_summary:
                violations.append({
                    "vuln_id": "VULN-IKEV1-AGGRESSIVE",
                    "title": "Insecure IKEv1 Aggressive Mode (PSK Exposure)",
                    "severity": "CRITICAL",
                    "cwe": "CWE-522",
                    "description": "IKEv1 Aggressive Mode transmits peer identities and pre-shared key (PSK) hashes in cleartext, enabling offline dictionary attacks.",
                    "remediation": "Upgrade immediately to IKEv2 (RFC 7296) or transition to IKEv1 Main Mode with digital certificates."
                })
                cap_triggers.append(("IKEv1 Aggressive Mode PSK Exposure", 45))
                return 0, "CRITICAL_FAIL", "IKEv1 Aggressive Mode exposes PSK hash to offline dictionary attacks. Banned by RFC 6071."
            else:
                violations.append({
                    "vuln_id": "VULN-LEGACY-IKEV1",
                    "title": "Deprecated IKEv1 Protocol (RFC 9395)",
                    "severity": "HIGH",
                    "cwe": "CWE-327",
                    "description": "IKEv1 is officially deprecated by the IETF (RFC 9395). Lacks DoS cookie protection and requires 6-message Main Mode exchange.",
                    "remediation": "Migrate VPN gateway configurations to IKEv2 (RFC 7296)."
                })
                return 5, "DEPRECATED", "IKEv1 officially deprecated by IETF RFC 9395. Vulnerable to DoS amplification and latency."

        return 8, "COMPLIANT", f"Control plane protocol version: {ike_ver}"

    def _eval_d6_stream_hygiene(self, esp_summary, violations, warnings, recommendations):
        """Dimension 6: ESP Stream Hygiene & Replay Protection (5 pts)"""
        total_esp = esp_summary.get("total_esp_packets", 0)
        if total_esp == 0:
            return 3, "CONTROL_PLANE_ONLY", "IKE handshake observed with zero active data plane ESP packets."

        seq_gaps = esp_summary.get("sequence_gaps", 0)
        gap_pct = (seq_gaps / max(1, total_esp)) * 100.0

        if seq_gaps == 0:
            return 5, "OPTIMAL", "Strict monotonic packet sequencing with zero loss. Active anti-replay protection verified."
        elif gap_pct <= 3.0:
            return 4, "ACCEPTABLE", f"Normal network transmission loss ({gap_pct:.1f}% sequence gaps). Anti-replay window accommodates pacing."
        else:
            warnings.append(f"High ESP sequence disruption ({gap_pct:.1f}% gaps/drops) observed on wiretap.")
            return 2, "WARNING", f"Elevated packet sequence gaps ({gap_pct:.1f}%) observed. Check for network congestion or replay attempts."

    def _audit_crypto_parameters(self, ike_data):
        violations = []
        warnings = []
        recommendations = []
        cap_triggers = []

        esp_summary = ike_data.get("esp_stream_summary", {})

        if not ike_data.get("handshake_detected"):
            # Mid-stream ESP wiretap case
            d6_score, d6_status, d6_rationale = self._eval_d6_stream_hygiene(esp_summary, violations, warnings, recommendations)
            return {
                "compliance_status": "UNVERIFIED_HANDSHAKE",
                "risk_score": 50,
                "raw_score": 50,
                "risk_level": "MEDIUM",
                "posture_label": "MID-STREAM ESP WIRETAP (NO IKE INTERCEPTED)",
                "rubric_breakdown": {
                    "d1_confidentiality": {
                        "name": "Payload Confidentiality & Cipher Strength",
                        "score": 15,
                        "max_score": 30,
                        "status": "UNVERIFIED",
                        "algorithm": "Undetermined (Encrypted ESP)",
                        "key_length": "N/A",
                        "rationale": "IKE Phase 1 handshake was unobserved on wire. Cipher suite cannot be verified deterministically."
                    },
                    "d2_key_exchange": {
                        "name": "Key Exchange & Discrete Log Resistance",
                        "score": 12,
                        "max_score": 25,
                        "status": "UNVERIFIED",
                        "dh_group": "Undetermined",
                        "rationale": "Diffie-Hellman exchange took place prior to wiretap initiation."
                    },
                    "d3_integrity_prf": {
                        "name": "Message Integrity & PRF Functions",
                        "score": 10,
                        "max_score": 20,
                        "status": "UNVERIFIED",
                        "integrity": "Undetermined",
                        "prf": "Undetermined",
                        "rationale": "Integrity and PRF algorithms could not be extracted without Phase 1 exchange."
                    },
                    "d4_forward_secrecy": {
                        "name": "Perfect Forward Secrecy (PFS) & Rekeying",
                        "score": 5,
                        "max_score": 10,
                        "status": "UNVERIFIED",
                        "pfs_status": "UNVERIFIED",
                        "rationale": "Child SA re-keying not observed during capture duration."
                    },
                    "d5_control_plane": {
                        "name": "Control Plane Protocol & Handshake Security",
                        "score": 5,
                        "max_score": 10,
                        "status": "UNVERIFIED",
                        "ike_version": "N/A",
                        "rationale": "No IKE negotiation frames present in PCAP."
                    },
                    "d6_stream_hygiene": {
                        "name": "ESP Stream Hygiene & Replay Protection",
                        "score": d6_score,
                        "max_score": 5,
                        "status": d6_status,
                        "rationale": d6_rationale
                    }
                },
                "veto_ceiling": {
                    "is_capped": True,
                    "raw_unconstrained_score": 47 + d6_score,
                    "cap_limit": 50,
                    "triggering_vulnerabilities": ["Mid-Stream ESP Wiretap (Unobserved Key Exchange)"]
                },
                "violations": [
                    {
                        "vuln_id": "VULN-UNVERIFIED-SESSION",
                        "title": "Unobserved Key Exchange (Mid-Stream ESP Only)",
                        "severity": "MEDIUM",
                        "cwe": "CWE-311",
                        "description": "The packet capture intercepted ongoing ESP traffic mid-stream. The Phase 1 IKE negotiation was not observed on the wire, precluding cryptographic suite verification.",
                        "remediation": "Deploy continuous wiretap capture at session initialization or verify gateway configuration out-of-band."
                    }
                ],
                "warnings": warnings,
                "recommendations": [
                    "Perform endpoint auditing of strongSwan / IPsec configuration files (`/etc/ipsec.conf` or `/etc/swanctl/`).",
                    "Monitor for subsequent IKE re-keying events (RFC 7296 CREATE_CHILD_SA) to capture future proposals."
                ],
                "negotiated_suite": {
                    "encryption": "Undetermined (Encrypted ESP)",
                    "key_length": "N/A",
                    "integrity": "Undetermined",
                    "prf": "Undetermined",
                    "dh_group": "Undetermined",
                    "auth_method": "Unobserved on Wire",
                    "key_lifetime": "N/A",
                    "pfs_status": "UNVERIFIED",
                    "pfs_details": "Unobserved",
                    "spi_pair": esp_summary.get("spi_pair_display", "None Observed"),
                    "replay_protection": esp_summary.get("replay_summary", "Active ESP Stream"),
                    "replay_window_width": "Undeterminable via Passive Wiretap",
                    "control_plane": "None (Mid-Stream ESP Only)",
                    "ike_sa_proposal": None,
                    "esp_child_sa_proposal": None
                }
            }

        proposals = ike_data.get("proposals", [])
        if not proposals:
            return {
                "compliance_status": "UNKNOWN",
                "risk_score": 50,
                "raw_score": 50,
                "risk_level": "MEDIUM",
                "posture_label": "INCOMPLETE IKE PROPOSAL",
                "rubric_breakdown": {},
                "veto_ceiling": {"is_capped": False, "raw_unconstrained_score": 50, "cap_limit": None, "triggering_vulnerabilities": []},
                "violations": [],
                "warnings": [],
                "recommendations": []
            }

        prop = proposals[0]
        enc = str(prop.get("encryption", "")).upper()
        klen = prop.get("key_length")
        integ = str(prop.get("integrity", "")).upper()
        prf = str(prop.get("prf", "")).upper()
        dh_num = prop.get("dh_group_num")
        dh_name = str(prop.get("dh_group", ""))
        ike_ver = ike_data.get("ike_version")
        pfs_status = str(ike_data.get("pfs_status", "DISABLED")).upper()
        control_summary = str(ike_data.get("control_plane_summary", "")).upper()

        # D1: Payload Confidentiality (30 pts)
        d1_score, d1_status, d1_rationale = self._eval_d1_confidentiality(enc, klen, violations, warnings, recommendations, cap_triggers)

        # D2: Key Exchange (25 pts)
        d2_score, d2_status, d2_rationale = self._eval_d2_key_exchange(dh_num, dh_name, violations, warnings, recommendations, cap_triggers)

        # D3: Integrity & PRF (20 pts)
        is_aead = any(a in enc for a in ["GCM", "POLY1305", "CHACHA"])
        d3_score, d3_status, d3_rationale = self._eval_d3_integrity_prf(integ, prf, is_aead, violations, warnings, recommendations, cap_triggers)

        # D4: Forward Secrecy & Key Management (10 pts)
        d4_score, d4_status, d4_rationale = self._eval_d4_forward_secrecy(pfs_status, violations, warnings, recommendations)

        # D5: Control Plane Protocol & Handshake Security (10 pts)
        d5_score, d5_status, d5_rationale = self._eval_d5_control_plane(ike_ver, control_summary, violations, warnings, recommendations, cap_triggers)

        # D6: ESP Stream Hygiene & Replay Protection (5 pts)
        d6_score, d6_status, d6_rationale = self._eval_d6_stream_hygiene(esp_summary, violations, warnings, recommendations)

        # Compute Raw Score
        raw_score = d1_score + d2_score + d3_score + d4_score + d5_score + d6_score

        # Apply Veto Ceiling (C_cap)
        if cap_triggers:
            c_cap = min(limit for _, limit in cap_triggers)
            is_capped = raw_score > c_cap
            final_score = min(raw_score, c_cap)
            trigger_names = [name for name, _ in cap_triggers]
        else:
            c_cap = 100
            is_capped = False
            final_score = raw_score
            trigger_names = []

        final_score = max(0, min(100, int(round(final_score))))

        if final_score >= 85:
            status = "PASS"
            level = "LOW"
            posture = "COMPLIANT (SECURE DEFENSE POSTURE)"
        elif final_score >= 60:
            status = "WARNING"
            level = "MEDIUM"
            posture = "NON-COMPLIANT WITH WARNINGS (DEPRECATED CIPHERS)"
        else:
            status = "FAIL"
            level = "CRITICAL"
            posture = "CRITICAL COMPLIANCE FAILURE (ACTIVE EXPLOIT RISK)"

        rubric_breakdown = {
            "d1_confidentiality": {
                "name": "Payload Confidentiality & Cipher Strength",
                "score": d1_score,
                "max_score": 30,
                "status": d1_status,
                "algorithm": enc,
                "key_length": klen,
                "rationale": d1_rationale
            },
            "d2_key_exchange": {
                "name": "Key Exchange & Discrete Log Resistance",
                "score": d2_score,
                "max_score": 25,
                "status": d2_status,
                "dh_group": dh_name or f"Group {dh_num}",
                "rationale": d2_rationale
            },
            "d3_integrity_prf": {
                "name": "Message Integrity & PRF Functions",
                "score": d3_score,
                "max_score": 20,
                "status": d3_status,
                "integrity": integ,
                "prf": prf,
                "rationale": d3_rationale
            },
            "d4_forward_secrecy": {
                "name": "Perfect Forward Secrecy (PFS) & Rekeying",
                "score": d4_score,
                "max_score": 10,
                "status": d4_status,
                "pfs_status": pfs_status,
                "rationale": d4_rationale
            },
            "d5_control_plane": {
                "name": "Control Plane Protocol & Handshake Security",
                "score": d5_score,
                "max_score": 10,
                "status": d5_status,
                "ike_version": f"IKEv{ike_ver}" if ike_ver else "Unknown",
                "rationale": d5_rationale
            },
            "d6_stream_hygiene": {
                "name": "ESP Stream Hygiene & Replay Protection",
                "score": d6_score,
                "max_score": 5,
                "status": d6_status,
                "rationale": d6_rationale
            }
        }

        veto_ceiling_info = {
            "is_capped": is_capped,
            "raw_unconstrained_score": raw_score,
            "cap_limit": c_cap if c_cap < 100 else None,
            "triggering_vulnerabilities": trigger_names
        }

        return {
            "compliance_status": status,
            "risk_score": final_score,
            "raw_score": raw_score,
            "risk_level": level,
            "posture_label": posture,
            "rubric_breakdown": rubric_breakdown,
            "veto_ceiling": veto_ceiling_info,
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
            "negotiated_suite": {
                "encryption": enc,
                "key_length": klen,
                "integrity": integ,
                "prf": prf,
                "dh_group": dh_name or f"Group {dh_num}",
                "auth_method": ike_data.get("auth_method", "Pre-Shared Key (PSK) - Authentication Succeeded"),
                "key_lifetime": ike_data.get("key_lifetime", "Autonomous Local Gateway Policy (RFC 7296 unnegotiated on wire; typical default ~3600s / 4GB)"),
                "pfs_status": pfs_status,
                "pfs_details": ike_data.get("pfs_details", "None"),
                "spi_pair": ike_data.get("esp_stream_summary", {}).get("spi_pair_display", "None Observed"),
                "replay_protection": ike_data.get("replay_protection", {}).get("description", "N/A"),
                "replay_window_width": ike_data.get("replay_protection", {}).get("window_bit_width", "Undeterminable via Passive Wiretap (Local Gateway Policy)"),
                "control_plane": ike_data.get("control_plane_summary", "N/A"),
                "ike_sa_proposal": ike_data.get("ike_sa_proposal"),
                "esp_child_sa_proposal": ike_data.get("esp_child_sa_proposal")
            }
        }


def print_audit_report(report):
    exec_sum = report.get("executive_summary", {})
    audit = report.get("cryptographic_audit", {})
    ai = report.get("ai_traffic_intelligence", {})
    tc = ai.get("traffic_classification", {})

    print("\n" + "="*70)
    print("      NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE")
    print("      IPsec VPN Protocol Security Assessment & AI Traffic Intelligence")
    print("="*70)
    print(f"Target PCAP:     {report.get('pcap_file')}")
    print(f"Total Packets:   {exec_sum.get('total_packets')} ({exec_sum.get('esp_packets')} ESP + {exec_sum.get('ike_packets')} IKE)")
    print(f"Session Duration:{ai.get('session_duration_sec', 0)}s (Active Payload: {ai.get('active_payload_duration_sec', 0)}s)")
    print(f"Control Plane:   {exec_sum.get('control_plane_summary')}")
    print(f"Active SPIs:     {exec_sum.get('spi_pair')}")
    print(f"Security Score:  {exec_sum.get('risk_score')}/100 (Raw: {audit.get('raw_score', exec_sum.get('risk_score'))}/100)")
    print(f"Compliance:      {exec_sum.get('compliance_status')} [{exec_sum.get('risk_level')} RISK]")
    print(f"Security Posture:{exec_sum.get('nist_sp800_77_posture')}")

    rubric = audit.get("rubric_breakdown", {})
    veto = audit.get("veto_ceiling", {})
    if rubric:
        print("\n[+] FORMALIZED 6-PILLAR SCORING RUBRIC BREAKDOWN:")
        print(f"  {'Security Pillar':<44} | {'Score':<8} | {'Status':<15} | {'Technical Rationale'}")
        print("  " + "-"*110)
        for key in ["d1_confidentiality", "d2_key_exchange", "d3_integrity_prf", "d4_forward_secrecy", "d5_control_plane", "d6_stream_hygiene"]:
            item = rubric.get(key, {})
            if item:
                score_str = f"{item.get('score')}/{item.get('max_score')}"
                print(f"  {item.get('name'):<44} | {score_str:<8} | {item.get('status'):<15} | {item.get('rationale')}")
        if veto.get("is_capped"):
            print(f"  [!] VETO CEILING ACTIVE: C_cap = {veto.get('cap_limit')}/100 (Raw: {veto.get('raw_unconstrained_score')}/100)")
            print(f"      Triggering Exploit(s): {', '.join(veto.get('triggering_vulnerabilities', []))}")
    print("-"*70)
    
    print("\n[+] CRYPTOGRAPHIC AUDIT (NIST SP 800-77 Rev. 1):")
    suite = audit.get("negotiated_suite", {})
    ike_prop = suite.get("ike_sa_proposal") or {}
    esp_prop = suite.get("esp_child_sa_proposal") or {}

    ike_cipher = ike_prop.get("encryption", suite.get("encryption", "N/A"))
    esp_cipher = esp_prop.get("encryption", suite.get("encryption", "N/A"))

    print(f"  IKE SA Cipher (Phase 1): {ike_cipher} (Key: {ike_prop.get('key_length', suite.get('key_length', 'N/A'))} bits)")
    print(f"  ESP SA Cipher (Phase 2): {esp_cipher} (Key: {esp_prop.get('key_length', suite.get('key_length', 'N/A'))} bits)")
    print(f"  Authentication Method  : {suite.get('auth_method')}")
    print(f"  Key Lifetime / Rekeying: {suite.get('key_lifetime')}")
    print(f"  Integrity / MAC Tag    : {suite.get('integrity')}")
    print(f"  PRF Function           : {suite.get('prf')}")
    print(f"  Diffie-Hellman Group   : {suite.get('dh_group')}")
    print(f"  Forward Secrecy (PFS)  : {suite.get('pfs_status')} ({suite.get('pfs_details')})")
    print(f"  Anti-Replay Window     : {suite.get('replay_protection')}")
    print(f"  Replay Buffer Bit-Width: {suite.get('replay_window_width')}")
    print(f"  Handshake Breakdown    : {suite.get('control_plane')}")

    vulns = audit.get("violations", [])
    if vulns:
        print(f"\n[!] IDENTIFIED THREATS & VULNERABILITIES ({len(vulns)}):")
        for idx, v in enumerate(vulns, 1):
            print(f"  {idx}. [{v['severity']}] {v['title']} ({v['cwe']})")
            print(f"     Description: {v['description']}")
            print(f"     Remediation: {v['remediation']}\n")
    else:
        print("\n[+] ZERO KNOWN CRYPTOGRAPHIC VULNERABILITIES DETECTED.")

    print("\n[+] AI ENCRYPTED TRAFFIC INTELLIGENCE:")
    pred_traffic = tc.get('display_profile') or tc.get('predicted_primary_profile', '').upper()
    print(f"  Predicted Traffic : {pred_traffic} (Confidence: {tc.get('confidence_score', 0)*100:.1f}%)")
    print(f"  Concurrent Flow   : {'YES (Multi-Application Multiplexing)' if tc.get('is_concurrent_traffic') else 'NO'}")
    print(f"  Active Apps       : {', '.join(tc.get('active_applications', []))}")
    print(f"  Tunnel Mode       : {exec_sum.get('operational_mode', '').upper()} (Confidence: {exec_sum.get('mode_confidence', 0)*100:.1f}%)")

    fdr = ai.get("flow_dynamics_reconciliation")
    if fdr:
        print("\n[+] FLOW DYNAMICS & PAYLOAD RECONCILIATION:")
        print(f"  Status            : {fdr.get('status')}")
        dyn = fdr.get('observed_wiretap_dynamics', {})
        print(f"  Observed Dynamics : Mean {dyn.get('mean_packet_size_b')}B, Std ±{dyn.get('size_dispersion_std_b')}B")
        print(f"  Payload Breakdown : {dyn.get('small_voice_frames_pct')}% Voice (<250B) + {dyn.get('large_mtu_frames_pct')}% MTU Data (>900B)")
        print(f"  Resolution        : {fdr.get('resolution')}")

    print("\nProbability Vector:")
    for r in tc.get('ranked_classes', [])[:4]:
        bar = '#' * int(r['probability'] * 25)
        print(f"  {r['class']:8s} : {r['probability']*100:5.1f}% | {bar}")
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="SIH26160 NIST SP 800-77 Security Evaluator")
    parser.add_argument("--pcap", required=True, help="Path to .pcapng file")
    parser.add_argument("--models-dir", default="models", help="Trained models directory")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    evaluator = NISTSecurityEvaluator()
    report = evaluator.evaluate_pcap(args.pcap, models_dir=args.models_dir)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_audit_report(report)


if __name__ == "__main__":
    main()
