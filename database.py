"""
Dual-State Database Persistence Engine for End-to-End Secure IoT Telemetry Pipeline
Persists verified telemetry analytics and encrypted at-rest ciphertext vault using aiosqlite.
Addresses IEEE Research Gap 4 (Plaintext Data Storage at Rest).
"""

import aiosqlite
import os
from typing import Dict, Any, List, Optional

DB_FILE_PATH = os.path.join(os.path.dirname(__file__), "telemetry_vault.db")


class DualStateDatabase:
    """
    Manages dual-state persistence:
    1. verified_telemetry: Plaintext sensor readings accessible to authorized queries
    2. encrypted_telemetry_vault: Cryptographic ciphertext blobs preserved at-rest for zero-trust audit
    3. security_audit_log: Log of dropped malicious/tampered packets and attack vectors
    """

    def __init__(self, db_path: str = DB_FILE_PATH):
        self.db_path = db_path
        self._initialized = False

    async def ensure_db(self):
        """Ensure schema is created if not already initialized."""
        if not self._initialized:
            await self.init_db()
            self._initialized = True

    async def init_db(self):
        """Initialize database schema with tables and indexes."""
        async with aiosqlite.connect(self.db_path) as db:
            # 1. Verified Telemetry (Plaintext analytics table)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS verified_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_id TEXT NOT NULL,
                    sensor_timestamp INTEGER NOT NULL,
                    temperature REAL NOT NULL,
                    humidity REAL NOT NULL,
                    verification_latency_us REAL NOT NULL,
                    crypto_overhead_us REAL NOT NULL
                )
            """)

            # 2. Encrypted Telemetry Vault (At-Rest encrypted raw ciphertext)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_telemetry_vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_id TEXT NOT NULL,
                    sensor_timestamp INTEGER NOT NULL,
                    nonce_hex TEXT NOT NULL,
                    ciphertext_hex TEXT NOT NULL,
                    tag_hex TEXT NOT NULL,
                    hmac_hex TEXT NOT NULL,
                    storage_state TEXT DEFAULT 'ENCRYPTED_AT_REST'
                )
            """)

            # 3. Security Audit Log (Dropped attacks & MitM attempts)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS security_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    attack_type TEXT NOT NULL,
                    source_device TEXT,
                    rejection_reason TEXT NOT NULL,
                    drop_latency_us REAL NOT NULL,
                    prevented_decryption_overhead_us REAL NOT NULL,
                    packet_snippet TEXT
                )
            """)

            await db.execute("CREATE INDEX IF NOT EXISTS idx_verified_device ON verified_telemetry(device_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_vault_device ON encrypted_telemetry_vault(device_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_attack ON security_audit_log(attack_type)")
            await db.commit()

    async def insert_dual_state(
        self,
        device_id: str,
        sensor_timestamp: int,
        temperature: float,
        humidity: float,
        verification_latency_us: float,
        crypto_overhead_us: float,
        nonce_hex: str,
        ciphertext_hex: str,
        tag_hex: str,
        hmac_hex: str
    ):
        """Simultaneously commit verified readings and raw encrypted payload."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO verified_telemetry (
                    device_id, sensor_timestamp, temperature, humidity,
                    verification_latency_us, crypto_overhead_us
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, sensor_timestamp, temperature, humidity, verification_latency_us, crypto_overhead_us))

            await db.execute("""
                INSERT INTO encrypted_telemetry_vault (
                    device_id, sensor_timestamp, nonce_hex, ciphertext_hex, tag_hex, hmac_hex, storage_state
                ) VALUES (?, ?, ?, ?, ?, ?, 'ENCRYPTED_AT_REST')
            """, (device_id, sensor_timestamp, nonce_hex, ciphertext_hex, tag_hex, hmac_hex))

            await db.commit()

    async def insert_security_audit(
        self,
        attack_type: str,
        source_device: str,
        rejection_reason: str,
        drop_latency_us: float,
        prevented_decryption_overhead_us: float,
        packet_snippet: str
    ):
        """Record an intercepted attack or malformed transmission in the audit vault."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO security_audit_log (
                    attack_type, source_device, rejection_reason,
                    drop_latency_us, prevented_decryption_overhead_us, packet_snippet
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (attack_type, source_device, rejection_reason, drop_latency_us, prevented_decryption_overhead_us, packet_snippet))
            await db.commit()

    async def get_recent_verified(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch latest verified telemetry entries."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM verified_telemetry ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_recent_vault(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch latest encrypted vault ciphertext blobs."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM encrypted_telemetry_vault ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_recent_audit_logs(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch latest security audit entries."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM security_audit_log ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_stats(self) -> Dict[str, Any]:
        """Aggregate summary counts and metrics for the SOC overview."""
        await self.ensure_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT COUNT(*) FROM verified_telemetry")
            (verified_count,) = await cursor.fetchone()

            cursor = await db.execute("SELECT COUNT(*) FROM encrypted_telemetry_vault")
            (vault_count,) = await cursor.fetchone()

            cursor = await db.execute("SELECT COUNT(*) FROM security_audit_log")
            (attack_count,) = await cursor.fetchone()

            # Breakdown by attack type
            cursor = await db.execute("""
                SELECT attack_type, COUNT(*) as count, AVG(drop_latency_us) as avg_latency
                FROM security_audit_log
                GROUP BY attack_type
            """)
            attack_breakdown = [dict(row) for row in await cursor.fetchall()]

            # Average verification latency
            cursor = await db.execute("SELECT AVG(verification_latency_us), AVG(crypto_overhead_us) FROM verified_telemetry")
            row = await cursor.fetchone()
            avg_verify = row[0] if row and row[0] else 0.0
            avg_crypto = row[1] if row and row[1] else 0.0

            return {
                "verified_count": verified_count,
                "vault_count": vault_count,
                "attack_count": attack_count,
                "attack_breakdown": attack_breakdown,
                "avg_verify_latency_us": round(avg_verify, 2),
                "avg_crypto_overhead_us": round(avg_crypto, 2)
            }
