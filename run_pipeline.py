"""
Single-Command Launcher for End-to-End Secure IoT Telemetry Pipeline & SOC Dashboard
Starts the FastAPI application with background sensor streaming, cryptographic defense gateway,
and real-time SOC web console.
"""

import uvicorn
import sys
import os

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8000
    
    print("=" * 75)
    print(" END-TO-END SECURE IoT TELEMETRY PIPELINE & SOC DASHBOARD")
    print(" ChaCha20-Poly1305 AEAD + HMAC-SHA256 Encrypt-then-MAC Defense Architecture")
    print("=" * 75)
    print(f"[*] Starting Cloud Security Gateway and SOC Web Dashboard...")
    print(f"[*] Access the interactive SOC Dashboard at: http://{host}:{port}")
    print(f"[*] Background sensor streaming: ACTIVE (ESP8266 / BME280 telemetry)")
    print("=" * 75)
    print("[*] Press Ctrl+C to terminate.")

    uvicorn.run("server:app", host=host, port=port, log_level="info", reload=False)
