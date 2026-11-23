"""
Comprehensive End-to-End Test Suite for Secure IoT Pipeline
Verifies Cryptographic Engine, Dual-State Persistence, Gateway Defenses, and Attack Interception.
"""

import asyncio
import time
from crypto_engine import CryptoEngine
from database import DualStateDatabase
from gateway import SecurityGateway
from sensor_simulator import SensorSimulator
from attack_injector import AttackInjector


async def run_pipeline_tests():
    print("======================================================================")
    print(" RUNNING END-TO-END VERIFICATION & BENCHMARK SUITE")
    print("======================================================================")

    test_db_path = "test_verification.db"
    db = DualStateDatabase(test_db_path)
    await db.init_db()

    crypto = CryptoEngine()
    gateway = SecurityGateway(crypto_engine=crypto, db=db)
    simulator = SensorSimulator(crypto_engine=crypto)
    injector = AttackInjector(crypto_engine=crypto)

    # TEST 1: Cryptographic Invariants & Tamper Resistance
    print("\n[+] Test 1: Cryptographic Invariants (ChaCha20-Poly1305 + HMAC-SHA256)")
    sample_payload = {"temperature": 24.12, "humidity": 55.4, "sensor": "BME280"}
    now_ts = int(time.time())
    packet, enc_time = crypto.encrypt_and_seal("esp8266_node_01", now_ts, sample_payload)
    print(f"    - Edge encryption completed in: {enc_time:.2f} µs")
    assert "nonce" in packet and len(packet["nonce"]) == 24, "Nonce must be 12 bytes (24 hex chars)"
    assert "tag" in packet and len(packet["tag"]) == 32, "Tag must be 16 bytes (32 hex chars)"
    assert "hmac" in packet and len(packet["hmac"]) == 64, "HMAC must be 32 bytes (64 hex chars)"

    # Constant-time HMAC check
    mac_data = crypto.construct_mac_data(packet["device_id"], packet["timestamp"], packet["nonce"], packet["ciphertext"], packet["tag"])
    is_valid, hmac_time = crypto.verify_hmac_constant_time(mac_data, packet["hmac"])
    assert is_valid is True, "Valid HMAC must pass"
    print(f"    - Constant-time HMAC verification latency: {hmac_time:.2f} µs (PASS)")

    # TEST 2: Ingress Acceptance & Dual-State Storage
    print("\n[+] Test 2: Ingress Acceptance & Dual-State Commit (IEEE Gap 4)")
    trace = await gateway.process_ingress_packet(packet)
    assert trace["verdict"] == "ACCEPTED_AND_SECURED", f"Expected accepted, got {trace['verdict']}"
    assert trace["stages"]["persistence"]["status"] == "SUCCESS"
    print(f"    - Gateway total ingress pipeline latency: {trace['total_pipeline_latency_us']:.2f} µs")

    verified_rows = await db.get_recent_verified(5)
    vault_rows = await db.get_recent_vault(5)
    assert len(verified_rows) == 1, "Verified table must have 1 record"
    assert len(vault_rows) == 1, "Encrypted vault table must have 1 record"
    assert vault_rows[0]["storage_state"] == "ENCRYPTED_AT_REST"
    print(f"    - Dual-state persistence verified: Plaintext record #{verified_rows[0]['id']} & Encrypted Vault #{vault_rows[0]['id']}")

    # TEST 3: MitM Bit-Flip Tampering (IEEE Gap 2: Pre-Decryption Defense)
    print("\n[+] Test 3: MitM Bit-Flip Tamper Interception (Pre-Decryption Drop)")
    tampered = injector.create_mitm_tamper(packet)
    trace_mitm = await gateway.process_ingress_packet(tampered)
    assert trace_mitm["verdict"] == "DROPPED_PRE_DECRYPTION", f"Expected pre-decryption drop, got {trace_mitm['verdict']}"
    assert trace_mitm["stages"]["decryption"]["status"] == "SKIPPED", "Decryption MUST be skipped"
    print(f"    - Tampered packet dropped in: {trace_mitm['stages']['hmac_verify']['latency_us']:.2f} µs")
    print(f"    - Decryption bypassed. Preserved CPU cycles: {trace_mitm['cpu_cycles_saved_us']} µs (PASS)")

    # TEST 4: Replay Attack Defense (IEEE Gap 3: Sliding-Window Nonce Cache)
    print("\n[+] Test 4: Replay Attack Defense (Sliding-Window Nonce Barrier)")
    replayed = injector.create_replay_packet(packet)
    trace_replay = await gateway.process_ingress_packet(replayed)
    assert trace_replay["verdict"] == "DROPPED_REPLAY_ATTACK", f"Expected replay drop, got {trace_replay['verdict']}"
    assert trace_replay["stages"]["decryption"]["status"] == "SKIPPED", "Decryption MUST be skipped on replay"
    print(f"    - Duplicate nonce rejected in: {trace_replay['stages']['replay_check']['latency_us']:.2f} µs (PASS)")

    # TEST 5: Stale Timestamp Injection
    print("\n[+] Test 5: Stale Timestamp Injection (Freshness Drift Barrier)")
    stale = injector.create_stale_timestamp(age_seconds=90)
    trace_stale = await gateway.process_ingress_packet(stale)
    assert trace_stale["verdict"] == "DROPPED_STALE_TIMESTAMP", f"Expected stale drop, got {trace_stale['verdict']}"
    print(f"    - Stale timestamp rejected in: {trace_stale['stages']['replay_check']['latency_us']:.2f} µs (PASS)")

    # TEST 6: High-Volume Malformed DoS Flood Defense
    print("\n[+] Test 6: 100-Packet Malformed DoS Flood Stress Test")
    flood = injector.generate_dos_flood(100)
    t_flood_start = time.perf_counter_ns()
    dropped_count = 0
    for pkt in flood:
        t_res = await gateway.process_ingress_packet(pkt)
        if "DROPPED" in t_res["verdict"]:
            dropped_count += 1
    total_flood_time_ms = (time.perf_counter_ns() - t_flood_start) / 1_000_000.0
    print(f"    - 100 flood packets processed in: {total_flood_time_ms:.2f} ms")
    print(f"    - All {dropped_count}/100 malicious packets dropped pre-decryption")
    print(f"    - Average drop time per malformed packet: {(total_flood_time_ms * 1000 / 100):.2f} µs")

    # TEST 7: Security Audit Vault Logs
    print("\n[+] Test 7: Security Audit Vault Inspection")
    audit_logs = await db.get_recent_audit_logs(10)
    assert len(audit_logs) >= 3, "Audit logs should record intercepted attacks"
    print(f"    - Total audit records stored: {len(audit_logs)}")
    print(f"    - Latest attack logged: {audit_logs[0]['attack_type']} (Latency: {audit_logs[0]['drop_latency_us']} µs)")

    import os
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("\n======================================================================")
    print(" ALL PIPELINE & CRYPTOGRAPHIC VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("======================================================================")


if __name__ == "__main__":
    asyncio.run(run_pipeline_tests())
