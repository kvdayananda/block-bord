import json
import os
from itsdangerous import Signer, BadSignature

# Import FastAPI's TestClient after FastAPI is installed
try:
    from fastapi.testclient import TestClient
except ImportError:
    # FastAPI may not be installed yet; defer monkey‑patch until import time
    TestClient = None

def _get_session_secret():
    try:
        from backend.app.config import settings
        return settings.session_secret
    except Exception:
        return os.getenv("SESSION_SECRET", "fallback-secret")

class _SessionTransaction:
    """Context manager mimicking Flask's ``client.session_transaction()``.

    It loads the existing signed ``session`` cookie (if present), exposes a mutable ``dict``
    that tests can modify, and writes the updated cookie back when the block exits. The
    cookie is signed using the same ``itsdangerous.Signer`` strategy that Starlette's
    ``SessionMiddleware`` employs (salt ``"starlette-session"``).
    """

    def __init__(self, client, secret: str):
        self.client = client
        self.secret = secret
        self.session_data = {}

    def __enter__(self):
        cookie = self.client.cookies.get("session")
        if cookie:
            signer = Signer(self.secret, salt="starlette-session")
            try:
                unsigned = signer.unsign(cookie).decode()
                self.session_data = json.loads(unsigned)
            except BadSignature:
                self.session_data = {}
        else:
            self.session_data = {}
        return self.session_data

    def __exit__(self, exc_type, exc, tb):
        signer = Signer(self.secret, salt="starlette-session")
        signed = signer.sign(json.dumps(self.session_data).encode()).decode()
        self.client.cookies.set("session", signed, domain="testserver")
        return False

def _patch_testclient():
    try:
        from fastapi.testclient import TestClient as _TC
    except ImportError:
        return
    if not hasattr(_TC, "session_transaction"):
        def session_transaction(self):
            secret = _get_session_secret()
            return _SessionTransaction(self, secret)
        setattr(_TC, "session_transaction", session_transaction)

_patch_testclient()
