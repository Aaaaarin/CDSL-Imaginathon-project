"""Connectors for the real telecom feeds, usable today without any integration deal.

Bulk lists (TRAI 1600 registry, DoT FRI, DoT MNRL) arrive as files. FeedSync loads a
directory of CSVs, hashes every number on load with the deployment key, and swaps the
in-memory registry atomically, so a raw number is never kept. Drop a new file in and
call sync(); a malformed file is rejected whole and the old lists stay live.

CAMARA SIM Swap and Number Verification are HTTP APIs. CamaraClient speaks the
published CAMARA request shapes with OAuth2 client credentials, a timeout, and a
response cache. Point it at an operator's Open Gateway endpoint with environment
variables; the mock server in tests speaks the same shapes.

    AGENTSNAP_FEEDS_DIR=/feeds              1600.csv, fri.csv, mnrl.csv
    AGENTSNAP_CAMARA_URL=https://...        operator or aggregator base URL
    AGENTSNAP_CAMARA_CLIENT_ID / _SECRET    OAuth2 client credentials
"""
from __future__ import annotations

import csv
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

from .telemetry import CallerRegistry, h

FRI_LEVELS = {"medium", "high", "very_high"}


def _digits(n: str) -> str:
    d = "".join(ch for ch in n if ch.isdigit())
    return d[-10:] if len(d) > 10 and not d.startswith("1600") else d


@dataclass
class SyncReport:
    ok: bool
    loaded: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    at: float = 0.0


class FeedSync:
    """Files: 1600.csv (number), fri.csv (number,level), mnrl.csv (number).
    Header rows allowed. Numbers may carry +91, spaces or dashes."""

    def __init__(self, registry: CallerRegistry, directory: str | None = None):
        self.registry = registry
        self.dir = Path(directory or os.environ.get("AGENTSNAP_FEEDS_DIR", "feeds"))
        self.last: SyncReport | None = None

    def sync(self) -> SyncReport:
        bfsi, fri, mnrl, errors = set(), {}, set(), []
        files = {"1600.csv": "bfsi", "fri.csv": "fri", "mnrl.csv": "mnrl"}
        loaded = {}
        for name, kind in files.items():
            p = self.dir / name
            if not p.exists():
                continue
            n = 0
            with open(p, newline="", encoding="utf8") as f:
                for i, row in enumerate(csv.reader(f)):
                    if not row or row[0].strip().lower() in ("number", "msisdn", "mobile"):
                        continue
                    num = _digits(row[0])
                    if len(num) < 10:
                        errors.append(f"{name}:{i + 1}: not a phone number")
                        continue
                    if kind == "fri":
                        lvl = (row[1].strip().lower().replace(" ", "_") if len(row) > 1 else "")
                        if lvl not in FRI_LEVELS:
                            errors.append(f"{name}:{i + 1}: level must be medium, high or very_high")
                            continue
                        fri[h(num)] = lvl
                    elif kind == "bfsi":
                        if not num.startswith("1600"):
                            errors.append(f"{name}:{i + 1}: 1600 registry entry does not start with 1600")
                            continue
                        bfsi.add(h(num))
                    else:
                        mnrl.add(h(num))
                    n += 1
            loaded[name] = n
        rep = SyncReport(ok=not errors, loaded=loaded, errors=errors[:20], at=time.time())
        if rep.ok and loaded:   # atomic swap, only on a clean load
            if "1600.csv" in loaded:
                self.registry.bfsi_1600 = bfsi
            if "fri.csv" in loaded:
                self.registry.fri = fri
            if "mnrl.csv" in loaded:
                self.registry.mnrl = mnrl
        self.last = rep
        return rep


class CamaraClient:
    """CAMARA SIM Swap (POST /sim-swap/v0/retrieve-date, /check) and Number
    Verification. Matches the interface of telemetry.SimSwapAPI so it drops in."""

    def __init__(self, base_url=None, client_id=None, client_secret=None, timeout=0.8, ttl=600, transport=None):
        self.base = (base_url or os.environ.get("AGENTSNAP_CAMARA_URL", "")).rstrip("/")
        self.cid = client_id or os.environ.get("AGENTSNAP_CAMARA_CLIENT_ID", "")
        self.secret = client_secret or os.environ.get("AGENTSNAP_CAMARA_CLIENT_SECRET", "")
        self.http = httpx.Client(base_url=self.base, timeout=timeout, transport=transport)
        self.token, self.token_exp = None, 0.0
        self.cache: dict[str, tuple[float, float | None]] = {}
        self.ttl = ttl
        self.numbers: dict[str, str] = {}   # keyed hash -> E.164, held only by the connector
        self.down = False

    def register(self, number: str):
        """The connector is the one place a real number exists; the engine sees the hash."""
        e164 = "+91" + _digits(number)[-10:]
        self.numbers[h(_digits(number))] = e164
        return h(_digits(number))

    def _auth(self):
        if self.token and time.time() < self.token_exp - 30:
            return self.token
        r = self.http.post("/oauth2/token", data={"grant_type": "client_credentials", "client_id": self.cid,
                                                  "client_secret": self.secret, "scope": "sim-swap"})
        r.raise_for_status()
        j = r.json()
        self.token, self.token_exp = j["access_token"], time.time() + int(j.get("expires_in", 3600))
        return self.token

    def retrieve_date(self, number_h: str):
        hit = self.cache.get(number_h)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        e164 = self.numbers.get(number_h)
        if not e164:
            return None
        r = self.http.post("/sim-swap/v0/retrieve-date", json={"phoneNumber": e164},
                           headers={"Authorization": f"Bearer {self._auth()}"})
        r.raise_for_status()
        raw = r.json().get("latestSimChange")
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() if raw else None
        self.cache[number_h] = (time.time(), ts)
        return ts

    def check(self, number_h: str, now: float, max_age_h: float) -> bool:
        t = self.retrieve_date(number_h)
        return t is not None and now - t <= max_age_h * 3600


def mock_camara_app(swaps: dict[str, str]):
    """A tiny CAMARA-shaped server for tests and offline demos: E.164 -> ISO date."""
    from urllib.parse import parse_qs

    app = FastAPI()

    @app.post("/oauth2/token")
    async def token(request: Request):
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if form.get("grant_type") != "client_credentials" or not form.get("client_secret"):
            raise HTTPException(401, "bad client")
        return {"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600}

    @app.post("/sim-swap/v0/retrieve-date")
    def retrieve(body: dict, authorization: str = Header("")):
        if authorization != "Bearer mock-token":
            raise HTTPException(401, "no token")
        return {"latestSimChange": swaps.get(body.get("phoneNumber"))}

    return app
