"""Real HTTPS listener and real loopback service, with disposable simulated radio."""

import asyncio
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid

import httpx
import pytest

pytest.importorskip("starlette")
uvicorn = pytest.importorskip("uvicorn")

from genesismesh_radio.console.app import ConsoleSettings, create_app  # noqa: E402
from genesismesh_radio.console.store import OperatorStore  # noqa: E402
from genesismesh_radio.console_cli import demo_bridge  # noqa: E402


@pytest.mark.skipif(not shutil.which("openssl"), reason="TLS fixture requires OpenSSL CLI")
def test_real_https_login_confirmation_and_revocation(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    store = OperatorStore()
    password = "disposable-https-password"
    store.set_user("owner", password, "operator")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
    try:
        with demo_bridge() as backend:
            config = uvicorn.Config(
                create_app(ConsoleSettings(origin), store, backend),
                ssl_certfile=str(cert),
                ssl_keyfile=str(key),
                proxy_headers=False,
                forwarded_allow_ips="",
                access_log=False,
                log_level="error",
                lifespan="off",
            )
            server = uvicorn.Server(config)
            worker = threading.Thread(
                target=lambda: asyncio.run(server.serve(sockets=[listener])), daemon=True
            )
            worker.start()
            try:
                deadline = time.monotonic() + 10
                while not server.started and worker.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert server.started
                context = ssl.create_default_context(cafile=str(cert))
                with httpx.Client(base_url=origin, verify=context, trust_env=False) as client:
                    headers = {"Origin": origin, "X-Console-Request": "1"}
                    assert client.get("/api/status").status_code == 401
                    response = client.post(
                        "/api/login",
                        headers=headers,
                        json={"username": "owner", "password": password},
                    )
                    assert response.status_code == 200
                    assert "Secure" in response.headers["set-cookie"]
                    headers["X-CSRF-Token"] = response.json()["csrf"]
                    identifier = str(uuid.uuid4())
                    request = {
                        "command_id": identifier,
                        "device_id": 1,
                        "interval_seconds": 60,
                        "ttl": 30,
                    }
                    assert (
                        client.post("/api/commands", headers=headers, json=request).status_code
                        == 202
                    )
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        result = client.get("/api/commands/" + identifier).json()["command"]
                        if result["state"] == "confirmed":
                            break
                        time.sleep(0.01)
                    assert result["state"] == "confirmed"
                    assert (
                        client.post("/api/commands", headers=headers, json=request).status_code
                        == 200
                    )
                    assert backend.status()["command_count"] == 1
                    store.revoke("owner")
                    assert client.get("/api/status").status_code == 401
                    assert (
                        client.post("/api/commands", headers=headers, json=request).status_code
                        == 401
                    )
            finally:
                server.should_exit = True
                worker.join(10)
                assert not worker.is_alive()
    finally:
        listener.close()
        store.close()
