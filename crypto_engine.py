"""
Cryptographic Engine for End-to-End Secure IoT Telemetry Pipeline
Implements ChaCha20-Poly1305 AEAD and HMAC-SHA256 Encrypt-then-MAC defense.
"""

import os
import time
import hmac
import hashlib
import json
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# System Default Keys (In production, loaded securely from environment / KMS)
DEFAULT_ENC_KEY = bytes.fromhex("1f8b4a7d6e5c3b2a90f1e2d3c4b5a697887766554433221100aabbccddeeff00")
DEFAULT_HMAC_KEY = bytes.fromhex("deadbeefcafebabe0123456789abcdef0123456789abcdefdeadbeefcafebabe")


class CryptoEngine:
    """
    Lightweight Application-Layer Cryptographic Engine for Resource-Constrained IoT Nodes
    and Cloud Security Gateway.
    """

    def __init__(self, enc_key: bytes = DEFAULT_ENC_KEY, hmac_key: bytes = DEFAULT_HMAC_KEY):
        if len(enc_key) != 32:
            raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")
        if len(hmac_key) != 32:
            raise ValueError("HMAC-SHA256 requires a 32-byte key.")
        self.enc_key = enc_key
        self.hmac_key = hmac_key
        self.aead = ChaCha20Poly1305(self.enc_key)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a cryptographically secure 12-byte random nonce (96 bits)."""
        return os.urandom(12)

    @staticmethod
    def construct_aad(device_id: str, timestamp: int) -> bytes:
        """
        Construct Associated Authenticated Data (AAD).
        Binds device identity and timestamp to the ciphertext at the AEAD layer.
        """
        return f"{device_id}:{timestamp}".encode("utf-8")

    @staticmethod
    def construct_mac_data(device_id: str, timestamp: int, nonce_hex: str, ciphertext_hex: str, tag_hex: str) -> bytes:
        """Construct canonical byte representation for Encrypt-then-MAC sealing."""
        return f"{device_id}|{timestamp}|{nonce_hex}|{ciphertext_hex}|{tag_hex}".encode("utf-8")

    def compute_hmac(self, mac_data: bytes) -> str:
        """Compute HMAC-SHA256 signature over data."""
        return hmac.new(self.hmac_key, mac_data, hashlib.sha256).hexdigest()

    def verify_hmac_constant_time(self, mac_data: bytes, received_hmac_hex: str) -> Tuple[bool, float]:
        """
        Constant-time HMAC-SHA256 verification (Pre-Decryption Defense).
        Returns (is_valid, elapsed_microseconds).
        """
        t_start = time.perf_counter_ns()
        computed_hmac = self.compute_hmac(mac_data)
        # Constant-time comparison prevents timing side-channel attacks
        is_valid = hmac.compare_digest(computed_hmac, received_hmac_hex)
        elapsed_us = (time.perf_counter_ns() - t_start) / 1000.0
        return is_valid, elapsed_us

    def encrypt_and_seal(self, device_id: str, timestamp: int, payload_data: Dict[str, Any], custom_nonce: Optional[bytes] = None) -> Tuple[Dict[str, Any], float]:
        """
        Encrypt sensor payload using ChaCha20-Poly1305 and seal with HMAC-SHA256 (Encrypt-then-MAC).
        Returns (wire_packet, encryption_time_microseconds).
        """
        t_start = time.perf_counter_ns()
        nonce = custom_nonce if custom_nonce is not None else self.generate_nonce()
        nonce_hex = nonce.hex()
        aad = self.construct_aad(device_id, timestamp)
        
        plaintext_bytes = json.dumps(payload_data, separators=(",", ":")).encode("utf-8")
        
        # ChaCha20-Poly1305 generates ciphertext + 16-byte authentication tag
        ct_and_tag = self.aead.encrypt(nonce, plaintext_bytes, aad)
        ciphertext_bytes = ct_and_tag[:-16]
        tag_bytes = ct_and_tag[-16:]
        
        ciphertext_hex = ciphertext_bytes.hex()
        tag_hex = tag_bytes.hex()

        # Step 2: Encrypt-then-MAC seal
        mac_data = self.construct_mac_data(device_id, timestamp, nonce_hex, ciphertext_hex, tag_hex)
        hmac_hex = self.compute_hmac(mac_data)
        
        elapsed_us = (time.perf_counter_ns() - t_start) / 1000.0
        
        wire_packet = {
            "device_id": device_id,
            "timestamp": timestamp,
            "nonce": nonce_hex,
            "ciphertext": ciphertext_hex,
            "tag": tag_hex,
            "hmac": hmac_hex
        }
        return wire_packet, elapsed_us

    def decrypt_payload(self, device_id: str, timestamp: int, nonce_hex: str, ciphertext_hex: str, tag_hex: str) -> Tuple[Optional[Dict[str, Any]], float, Optional[str]]:
        """
        Decrypt ChaCha20-Poly1305 ciphertext using AAD verification.
        Returns (decrypted_json_or_None, decryption_time_microseconds, error_message).
        """
        t_start = time.perf_counter_ns()
        try:
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            tag = bytes.fromhex(tag_hex)
            aad = self.construct_aad(device_id, timestamp)
            
            ct_and_tag = ciphertext + tag
            decrypted_bytes = self.aead.decrypt(nonce, ct_and_tag, aad)
            payload = json.loads(decrypted_bytes.decode("utf-8"))
            elapsed_us = (time.perf_counter_ns() - t_start) / 1000.0
            return payload, elapsed_us, None
        except Exception as e:
            elapsed_us = (time.perf_counter_ns() - t_start) / 1000.0
            return None, elapsed_us, str(e)


# Self-test block
if __name__ == "__main__":
    engine = CryptoEngine()
    test_reading = {"temperature": 24.35, "humidity": 58.2, "sensor": "BME280"}
    packet, enc_time = engine.encrypt_and_seal("esp8266_01", int(time.time()), test_reading)
    print(f"Encrypted in {enc_time:.2f} µs: {packet}")
    
    # Verify HMAC
    mac_data = engine.construct_mac_data(packet["device_id"], packet["timestamp"], packet["nonce"], packet["ciphertext"], packet["tag"])
    is_valid, mac_time = engine.verify_hmac_constant_time(mac_data, packet["hmac"])
    print(f"HMAC Verified: {is_valid} in {mac_time:.2f} µs")
    
    # Decrypt
    decrypted, dec_time, err = engine.decrypt_payload(packet["device_id"], packet["timestamp"], packet["nonce"], packet["ciphertext"], packet["tag"])
    print(f"Decrypted in {dec_time:.2f} µs: {decrypted}")
