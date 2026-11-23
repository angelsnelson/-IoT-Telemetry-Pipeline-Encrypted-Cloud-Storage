"""
Cyber-Attack Simulation Engine
Simulates Man-in-the-Middle (MitM) payload tampering, packet replay, stale timestamps,
forged signatures, and DoS malformed packet floods to validate gateway defenses.
"""

import time
import random
from typing import Dict, Any, List, Optional
from crypto_engine import CryptoEngine


class AttackInjector:
    """
    Generates controlled attack vectors against the IoT security pipeline.
    """

    def __init__(self, crypto_engine: Optional[CryptoEngine] = None):
        self.crypto = crypto_engine or CryptoEngine()

    def create_mitm_tamper(self, valid_packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Man-in-the-Middle Tamper Attack:
        Flips bits in the ciphertext or modifies the ciphertext string, simulating wire eavesdropper
        alteration without possessing the HMAC authentication key.
        """
        tampered = dict(valid_packet)
        ct = tampered.get("ciphertext", "")
        if ct:
            # Flip middle characters in hex string
            mid = len(ct) // 2
            flipped_char = '0' if ct[mid] != '0' else 'f'
            tampered["ciphertext"] = ct[:mid] + flipped_char + ct[mid+1:]
        else:
            tampered["ciphertext"] = "deadbeefcafebabe"
        return tampered

    def create_replay_packet(self, past_packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Replay Attack:
        Re-transmits an authentic historical packet without modification to bypass
        HMAC checks but test the sliding-window nonce barrier.
        """
        # Exact copy of past legitimate packet
        return dict(past_packet)

    def create_stale_timestamp(self, age_seconds: int = 120, device_id: str = "esp8266_bme280_01") -> Dict[str, Any]:
        """
        Stale Timestamp Injection:
        Transmits a packet cryptographically valid, but with timestamp older than
        the gateway's allowable freshness window (e.g. 120 seconds old).
        """
        stale_time = int(time.time()) - age_seconds
        fake_reading = {"temperature": 24.0, "humidity": 50.0, "attack": "stale_timestamp"}
        packet, _ = self.crypto.encrypt_and_seal(device_id, stale_time, fake_reading)
        return packet

    def create_forged_hmac(self, valid_packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Forged Signature Attack:
        Substitutes the HMAC with random hex to test constant-time rejection.
        """
        forged = dict(valid_packet)
        forged["hmac"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        return forged

    def generate_dos_flood(self, burst_count: int = 100) -> List[Dict[str, Any]]:
        """
        High-Rate Malformed DoS Flood:
        Generates a barrage of malformed packets to evaluate gateway throughput
        and verify that pre-decryption drops consume sub-microsecond CPU cycles.
        """
        flood_packets = []
        now = int(time.time())
        for i in range(burst_count):
            flood_packets.append({
                "device_id": f"botnet_attacker_{random.randint(1000, 9999)}",
                "timestamp": now - random.randint(0, 10),
                "nonce": f"{random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFF):024x}",
                "ciphertext": f"{random.randint(0, 0xFFFFFFFFFFFFFFFF):016x}",
                "tag": f"{random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):032x}",
                "hmac": f"{random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):064x}"
            })
        return flood_packets
