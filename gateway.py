"""
Cloud Security Gateway with Encrypt-then-MAC Pre-Decryption Defense Architecture
Implements constant-time HMAC pre-validation, sliding-window nonce replay protection,
ChaCha20-Poly1305 decryption, and dual-state persistence.
Addresses IEEE Research Gaps 2 & 3.
"""

import time
import json
from collections import deque
from typing import Dict, Any, Tuple, Optional, Set
from crypto_engine import CryptoEngine
from database import DualStateDatabase


class SecurityGateway:
    """
    High-Throughput Cloud Security Gateway implementing Encrypt-then-MAC Pre-Decryption Defense.
    """

    def __init__(
        self,
        crypto_engine: Optional[CryptoEngine] = None,
        db: Optional[DualStateDatabase] = None,
        max_time_drift_seconds: int = 30,
        nonce_window_size: int = 5000
    ):
        self.crypto = crypto_engine or CryptoEngine()
        self.db = db or DualStateDatabase()
        self.max_time_drift = max_time_drift_seconds
        
        # Sliding-Window Nonce Cache: O(1) membership checks with set + FIFO eviction deque
        self.nonce_window_size = nonce_window_size
        self.nonce_deque: deque = deque()
        self.nonce_set: Set[str] = set()

        # Telemetry metrics
        self.total_packets_received = 0
        self.total_packets_accepted = 0
        self.total_packets_rejected = 0
        self.total_cpu_saved_us = 0.0

    def _is_nonce_in_cache(self, nonce_hex: str) -> bool:
        """O(1) lookup in sliding-window nonce cache."""
        return nonce_hex in self.nonce_set

    def _add_nonce_to_cache(self, nonce_hex: str):
        """Add nonce and maintain bounded sliding window."""
        if len(self.nonce_deque) >= self.nonce_window_size:
            oldest_nonce = self.nonce_deque.popleft()
            self.nonce_set.discard(oldest_nonce)
        self.nonce_deque.append(nonce_hex)
        self.nonce_set.add(nonce_hex)

    async def process_ingress_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the 4-stage Encrypt-then-MAC Pre-Decryption Defense Pipeline.
        Returns a complete pipeline trace event for SOC visualizer.
        """
        self.total_packets_received += 1
        t_ingress = time.perf_counter_ns()
        current_time = int(time.time())

        trace = {
            "packet_id": self.total_packets_received,
            "received_at_timestamp": current_time,
            "device_id": packet.get("device_id", "unknown"),
            "nonce": packet.get("nonce", ""),
            "stages": {
                "ingress": {"status": "SUCCESS", "latency_us": 0.0},
                "hmac_verify": {"status": "PENDING", "latency_us": 0.0, "details": ""},
                "replay_check": {"status": "PENDING", "latency_us": 0.0, "details": ""},
                "decryption": {"status": "SKIPPED", "latency_us": 0.0, "details": ""},
                "persistence": {"status": "SKIPPED", "latency_us": 0.0, "details": ""}
            },
            "verdict": "REJECTED",
            "reason": "",
            "telemetry": None,
            "cpu_cycles_saved_us": 0.0
        }

        # Validate required wire format fields
        required_fields = ["device_id", "timestamp", "nonce", "ciphertext", "tag", "hmac"]
        if not all(field in packet for field in required_fields):
            trace["reason"] = "MALFORMED_PACKET_STRUCTURE"
            trace["stages"]["ingress"]["status"] = "FAILED"
            self.total_packets_rejected += 1
            return trace

        device_id = str(packet["device_id"])
        pkt_timestamp = int(packet["timestamp"])
        nonce_hex = str(packet["nonce"])
        ciphertext_hex = str(packet["ciphertext"])
        tag_hex = str(packet["tag"])
        received_hmac = str(packet["hmac"])

        # =========================================================================
        # STAGE 1: PRE-DECRYPTION HMAC-SHA256 VERIFICATION (CONSTANT-TIME)
        # Drops tampered, forged, or corrupt payloads BEFORE decryption is attempted.
        # =========================================================================
        mac_data = self.crypto.construct_mac_data(device_id, pkt_timestamp, nonce_hex, ciphertext_hex, tag_hex)
        is_hmac_valid, hmac_latency_us = self.crypto.verify_hmac_constant_time(mac_data, received_hmac)
        trace["stages"]["hmac_verify"]["latency_us"] = round(hmac_latency_us, 2)

        if not is_hmac_valid:
            # Reject immediately - save AEAD decryption CPU overhead (~40-60 µs saved per packet)
            trace["stages"]["hmac_verify"]["status"] = "FAILED"
            trace["stages"]["hmac_verify"]["details"] = "HMAC mismatch! Bit-flip or forgery detected."
            trace["verdict"] = "DROPPED_PRE_DECRYPTION"
            trace["reason"] = "ATTACK_MITM_TAMPER_DETECTED"
            
            # Estimated AEAD decryption cost avoided
            estimated_aead_cost = 45.0
            trace["cpu_cycles_saved_us"] = estimated_aead_cost
            self.total_cpu_saved_us += estimated_aead_cost
            self.total_packets_rejected += 1

            # Log to SQLite security audit vault
            await self.db.insert_security_audit(
                attack_type="MITM_TAMPER",
                source_device=device_id,
                rejection_reason="Invalid HMAC-SHA256 signature in constant-time pre-check",
                drop_latency_us=hmac_latency_us,
                prevented_decryption_overhead_us=estimated_aead_cost,
                packet_snippet=f"Nonce: {nonce_hex[:8]}... CT: {ciphertext_hex[:16]}..."
            )
            return trace

        trace["stages"]["hmac_verify"]["status"] = "SUCCESS"
        trace["stages"]["hmac_verify"]["details"] = "Constant-time signature valid."

        # =========================================================================
        # STAGE 2: FRESHNESS & SLIDING-WINDOW REPLAY ATTACK DEFENSE
        # Validates timestamp window and nonce uniqueness to prevent replay.
        # =========================================================================
        t_replay_start = time.perf_counter_ns()
        time_diff = abs(current_time - pkt_timestamp)

        if time_diff > self.max_time_drift:
            replay_latency_us = (time.perf_counter_ns() - t_replay_start) / 1000.0
            trace["stages"]["replay_check"]["status"] = "FAILED"
            trace["stages"]["replay_check"]["latency_us"] = round(replay_latency_us, 2)
            trace["stages"]["replay_check"]["details"] = f"Stale timestamp (Δt = {time_diff}s > {self.max_time_drift}s window)"
            trace["verdict"] = "DROPPED_STALE_TIMESTAMP"
            trace["reason"] = "ATTACK_STALE_TIMESTAMP_DETECTED"
            self.total_packets_rejected += 1

            await self.db.insert_security_audit(
                attack_type="STALE_TIMESTAMP",
                source_device=device_id,
                rejection_reason=f"Timestamp drift of {time_diff}s exceeded maximum {self.max_time_drift}s",
                drop_latency_us=replay_latency_us,
                prevented_decryption_overhead_us=45.0,
                packet_snippet=f"Packet time: {pkt_timestamp}, Gateway time: {current_time}"
            )
            return trace

        if self._is_nonce_in_cache(nonce_hex):
            replay_latency_us = (time.perf_counter_ns() - t_replay_start) / 1000.0
            trace["stages"]["replay_check"]["status"] = "FAILED"
            trace["stages"]["replay_check"]["latency_us"] = round(replay_latency_us, 2)
            trace["stages"]["replay_check"]["details"] = f"Nonce {nonce_hex[:8]}... already committed in replay window!"
            trace["verdict"] = "DROPPED_REPLAY_ATTACK"
            trace["reason"] = "ATTACK_REPLAY_DETECTED"
            self.total_packets_rejected += 1

            await self.db.insert_security_audit(
                attack_type="REPLAY_ATTACK",
                source_device=device_id,
                rejection_reason="Duplicate nonce detected within sliding-window cache",
                drop_latency_us=replay_latency_us,
                prevented_decryption_overhead_us=45.0,
                packet_snippet=f"Replayed Nonce: {nonce_hex}"
            )
            return trace

        # Nonce is unique and fresh: commit to sliding window
        self._add_nonce_to_cache(nonce_hex)
        replay_latency_us = (time.perf_counter_ns() - t_replay_start) / 1000.0
        trace["stages"]["replay_check"]["status"] = "SUCCESS"
        trace["stages"]["replay_check"]["latency_us"] = round(replay_latency_us, 2)
        trace["stages"]["replay_check"]["details"] = f"Unique nonce committed. (Window size: {len(self.nonce_deque)})"

        # =========================================================================
        # STAGE 3: CHACHA20-POLY1305 AEAD DECRYPTION
        # Only reached after HMAC integrity and replay protection have passed.
        # =========================================================================
        decrypted_payload, dec_latency_us, dec_err = self.crypto.decrypt_payload(
            device_id, pkt_timestamp, nonce_hex, ciphertext_hex, tag_hex
        )
        trace["stages"]["decryption"]["latency_us"] = round(dec_latency_us, 2)

        if dec_err is not None or decrypted_payload is None:
            trace["stages"]["decryption"]["status"] = "FAILED"
            trace["stages"]["decryption"]["details"] = f"Decryption error: {dec_err}"
            trace["verdict"] = "DROPPED_DECRYPTION_FAILED"
            trace["reason"] = "CRYPTO_POLY1305_AEAD_ERROR"
            self.total_packets_rejected += 1
            return trace

        trace["stages"]["decryption"]["status"] = "SUCCESS"
        trace["stages"]["decryption"]["details"] = "ChaCha20-Poly1305 AEAD verified & decrypted."
        trace["telemetry"] = decrypted_payload

        # =========================================================================
        # STAGE 4: DUAL-STATE STORAGE COMMIT
        # Commits verified telemetry AND encrypted raw ciphertext to SQLite.
        # =========================================================================
        t_db_start = time.perf_counter_ns()
        total_verify_latency = hmac_latency_us + replay_latency_us
        total_crypto_overhead = total_verify_latency + dec_latency_us

        temp = float(decrypted_payload.get("temperature", 0.0))
        hum = float(decrypted_payload.get("humidity", 0.0))

        await self.db.insert_dual_state(
            device_id=device_id,
            sensor_timestamp=pkt_timestamp,
            temperature=temp,
            humidity=hum,
            verification_latency_us=round(total_verify_latency, 2),
            crypto_overhead_us=round(total_crypto_overhead, 2),
            nonce_hex=nonce_hex,
            ciphertext_hex=ciphertext_hex,
            tag_hex=tag_hex,
            hmac_hex=received_hmac
        )

        db_latency_us = (time.perf_counter_ns() - t_db_start) / 1000.0
        trace["stages"]["persistence"]["status"] = "SUCCESS"
        trace["stages"]["persistence"]["latency_us"] = round(db_latency_us, 2)
        trace["stages"]["persistence"]["details"] = "Dual-state committed: verified table + encrypted at-rest vault."

        trace["verdict"] = "ACCEPTED_AND_SECURED"
        trace["reason"] = "AUTHENTIC_TELEMETRY"
        self.total_packets_accepted += 1

        total_latency_us = (time.perf_counter_ns() - t_ingress) / 1000.0
        trace["total_pipeline_latency_us"] = round(total_latency_us, 2)

        return trace
