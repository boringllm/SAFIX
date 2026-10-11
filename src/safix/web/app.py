"""SAFIX web UI entry point."""

from __future__ import annotations

from .api import create_app

app = create_app()


def run(host: str = "127.0.0.1", port: int = 8375) -> None:
    import uvicorn
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: SAFIX web UI exposes endpoints that read and tail arbitrary server-side "
              "files (upload scan, live watch). Binding to a non-loopback address makes these "
              f"reachable by anyone who can reach {host}:{port}. Use a trusted network only, and "
              "put an authenticating reverse proxy in front if it must be remote.")
    print(f"SAFIX web UI → http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
