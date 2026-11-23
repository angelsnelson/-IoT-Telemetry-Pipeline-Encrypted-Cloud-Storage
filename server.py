"""
FastAPI Server for End-to-End Secure IoT Telemetry Pipeline & SOC Dashboard
Provides WebSocket real-time push, REST endpoints for attack simulations,
database queries, and serves the SOC dashboard UI.
"""

import asyncio
import json
import time
import os
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from crypto_engine import CryptoEngine
from database import DualStateDatabase, DB_FILE_PATH
from gateway import SecurityGateway
from sensor_simulator import SensorSimulator
from attack_injector import AttackInjector

# Connection manager for SOC WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                disconnected.append(connection)
        for dead_conn in disconnected:
            self.disconnect(dead_conn)


# Global instances
crypto_engine = CryptoEngine()
database = DualStateDatabase(DB_FILE_PATH)
gateway = SecurityGateway(crypto_engine=crypto_engine, db=database)
simulator = SensorSimulator(crypto_engine=crypto_engine)
attack_injector = AttackInjector(crypto_engine=crypto_engine)
ws_manager = ConnectionManager()

# Background streaming state
streaming_active = True
stream_interval_seconds = 1.8
last_valid_packet: Optional[Dict[str, Any]] = None
stream_task: Optional[asyncio.Task] = None


async def background_sensor_loop():
    """Continuously stream live, open-source physical IoT sensor readings through security gateway."""
    global last_valid_packet, streaming_active, stream_interval_seconds
    while True:
        try:
            if streaming_active:
                # Produce encrypted and sealed packet from real-world open-source IoT network
                wire_packet, raw_reading, edge_crypto_time = await simulator.produce_live_encrypted_packet()
                last_valid_packet = wire_packet

                # Process through pre-decryption defense gateway
                trace = await gateway.process_ingress_packet(wire_packet)
                trace["edge_crypto_time_us"] = edge_crypto_time
                trace["raw_sensor_data"] = raw_reading
                trace["station_name"] = raw_reading.get("station_name", "Live Station")
                trace["city"] = raw_reading.get("city", "Europe/Global")
                trace["hardware_sensor"] = raw_reading.get("hardware_sensor", "BME280")
                trace["source_platform"] = raw_reading.get("source_platform", "OpenSenseMap Live")

                # Broadcast trace & stats to connected SOC dashboard clients
                stats = await database.get_stats()
                stats["gateway_received"] = gateway.total_packets_received
                stats["gateway_accepted"] = gateway.total_packets_accepted
                stats["gateway_rejected"] = gateway.total_packets_rejected
                stats["cpu_saved_us"] = round(gateway.total_cpu_saved_us, 2)
                stats["active_source"] = simulator.live_client.active_source_name

                await ws_manager.broadcast({
                    "event": "packet_event",
                    "trace": trace,
                    "stats": stats
                })

            await asyncio.sleep(stream_interval_seconds)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Streamer Error]: {e}")
            await asyncio.sleep(1.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database and background streaming task
    await database.init_db()
    global stream_task
    stream_task = asyncio.create_task(background_sensor_loop())
    print("[SOC Server] Database initialized and background sensor streamer started.")
    yield
    # Shutdown
    if stream_task:
        stream_task.cancel()
        try:
            await stream_task
        except asyncio.CancelledError:
            pass
    print("[SOC Server] Shutdown complete.")


app = FastAPI(title="Secure IoT Telemetry SOC Gateway", lifespan=lifespan)

# Request schemas
class AttackTriggerRequest(BaseModel):
    attack_type: str  # 'mitm_tamper', 'replay', 'stale_timestamp', 'forged_hmac', 'dos_flood'
    burst_count: Optional[int] = 50


class StreamerConfigRequest(BaseModel):
    active: Optional[bool] = None
    interval: Optional[float] = None


# REST Endpoints
@app.post("/api/attacks/trigger")
async def trigger_attack(req: AttackTriggerRequest):
    """Inject a cyber-attack into the live gateway pipeline."""
    global last_valid_packet
    attack_type = req.attack_type
    traces = []

    if attack_type == "mitm_tamper":
        # Create tamper from last valid packet or generate fresh one
        base_packet = last_valid_packet or simulator.produce_encrypted_packet()[0]
        tampered_packet = attack_injector.create_mitm_tamper(base_packet)
        trace = await gateway.process_ingress_packet(tampered_packet)
        traces.append(trace)

    elif attack_type == "replay":
        if not last_valid_packet:
            # Generate one legitimate packet first, process it, then replay it
            legit_packet, _, _ = simulator.produce_encrypted_packet()
            await gateway.process_ingress_packet(legit_packet)
            last_valid_packet = legit_packet
        
        replayed_packet = attack_injector.create_replay_packet(last_valid_packet)
        trace = await gateway.process_ingress_packet(replayed_packet)
        traces.append(trace)

    elif attack_type == "stale_timestamp":
        stale_packet = attack_injector.create_stale_timestamp(age_seconds=120)
        trace = await gateway.process_ingress_packet(stale_packet)
        traces.append(trace)

    elif attack_type == "forged_hmac":
        base_packet = last_valid_packet or simulator.produce_encrypted_packet()[0]
        forged_packet = attack_injector.create_forged_hmac(base_packet)
        trace = await gateway.process_ingress_packet(forged_packet)
        traces.append(trace)

    elif attack_type == "dos_flood":
        count = min(req.burst_count or 50, 200)
        flood_packets = attack_injector.generate_dos_flood(count)
        for pkt in flood_packets:
            trace = await gateway.process_ingress_packet(pkt)
            traces.append(trace)

    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack type: {attack_type}")

    # Broadcast attack event to SOC UI
    stats = await database.get_stats()
    stats["gateway_received"] = gateway.total_packets_received
    stats["gateway_accepted"] = gateway.total_packets_accepted
    stats["gateway_rejected"] = gateway.total_packets_rejected
    stats["cpu_saved_us"] = round(gateway.total_cpu_saved_us, 2)

    for tr in traces[:5]:  # Send at least first few traces to avoid overwhelming UI if DoS
        await ws_manager.broadcast({
            "event": "attack_alert",
            "attack_type": attack_type,
            "trace": tr,
            "total_attack_packets": len(traces),
            "stats": stats
        })

    return {
        "status": "ATTACK_EXECUTED",
        "attack_type": attack_type,
        "packets_injected": len(traces),
        "primary_trace": traces[0] if traces else None,
        "stats": stats
    }


@app.get("/api/stats")
async def get_system_stats():
    """Retrieve aggregate pipeline statistics and attack breakdown."""
    stats = await database.get_stats()
    stats["gateway_received"] = gateway.total_packets_received
    stats["gateway_accepted"] = gateway.total_packets_accepted
    stats["gateway_rejected"] = gateway.total_packets_rejected
    stats["cpu_saved_us"] = round(gateway.total_cpu_saved_us, 2)
    stats["streamer_active"] = streaming_active
    stats["stream_interval"] = stream_interval_seconds
    stats["nonce_cache_size"] = len(gateway.nonce_deque)
    return stats


@app.get("/api/database/verified")
async def get_verified_telemetry(limit: int = 15):
    """Retrieve recent verified telemetry records."""
    return await database.get_recent_verified(limit)


@app.get("/api/database/vault")
async def get_encrypted_vault(limit: int = 15):
    """Retrieve raw encrypted at-rest ciphertext records."""
    return await database.get_recent_vault(limit)


@app.get("/api/database/audit")
async def get_audit_logs(limit: int = 15):
    """Retrieve security audit logs of intercepted attacks."""
    return await database.get_recent_audit_logs(limit)


@app.post("/api/streamer/config")
async def config_streamer(cfg: StreamerConfigRequest):
    """Toggle streaming or modify transmission frequency."""
    global streaming_active, stream_interval_seconds
    if cfg.active is not None:
        streaming_active = cfg.active
    if cfg.interval is not None and cfg.interval >= 0.2:
        stream_interval_seconds = cfg.interval
    return {
        "streaming_active": streaming_active,
        "stream_interval": stream_interval_seconds
    }


# WebSocket endpoint for real-time SOC updates
@app.websocket("/ws/soc")
async def websocket_soc_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial state snapshot on connect
        stats = await database.get_stats()
        stats["gateway_received"] = gateway.total_packets_received
        stats["gateway_accepted"] = gateway.total_packets_accepted
        stats["gateway_rejected"] = gateway.total_packets_rejected
        stats["cpu_saved_us"] = round(gateway.total_cpu_saved_us, 2)
        recent_verified = await database.get_recent_verified(10)
        recent_vault = await database.get_recent_vault(10)
        recent_audit = await database.get_recent_audit_logs(10)

        await websocket.send_text(json.dumps({
            "event": "initial_state",
            "stats": stats,
            "recent_verified": recent_verified,
            "recent_vault": recent_vault,
            "recent_audit": recent_audit
        }))

        # Keep listening for any client commands (e.g. ping/heartbeat)
        while True:
            data = await websocket.receive_text()
            # Can accept client-side trigger commands over WS
            try:
                cmd = json.loads(data)
                if cmd.get("action") == "ping":
                    await websocket.send_text(json.dumps({"event": "pong", "time": time.time()}))
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# Mount static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>SOC Dashboard Initializing...</h1>")
