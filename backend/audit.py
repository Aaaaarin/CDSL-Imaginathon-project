"""Hash-chained decision log, signed checkpoints, and the input event log.

Every decision is appended as h_i = SHA-256(h_{i-1} || canonical_json(record_i)).
Changing, inserting or deleting any record breaks every later link, and verify()
names the first broken sequence number.

A hash chain alone does not stop an insider who rewrites the whole table and
recomputes every hash. So every `checkpoint_every` records the head is signed with
an Ed25519 key that lives outside the database (an HSM in production; a key file
or an ephemeral key here). Verification checks every signature against the public
key, which can be published to SEBI or any auditor.

The event log stores each input event exactly as received, so the engine can be
rebuilt after a crash: restore the last snapshot, then replay the log after it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64


try:
    import orjson

    _OPTS = orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS

    def canon(obj) -> str:
        """Canonical JSON (sorted keys, no spaces). orjson is ~10x faster than json
        here, and this runs twice per event (input log and audit chain)."""
        return orjson.dumps(obj, option=_OPTS, default=str).decode()
except ImportError:  # pragma: no cover
    def canon(obj) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def load_signing_key(path: str | None = None, passphrase: str | None = None) -> Ed25519PrivateKey:
    """AGENTSNAP_SIGNING_KEY points at a PEM file, encrypted with
    AGENTSNAP_KEY_PASSPHRASE when set. Without a file an ephemeral key is used."""
    path = path or os.environ.get("AGENTSNAP_SIGNING_KEY")
    pw = passphrase if passphrase is not None else os.environ.get("AGENTSNAP_KEY_PASSPHRASE")
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=pw.encode() if pw else None)
    return Ed25519PrivateKey.generate()


def save_signing_key(key: Ed25519PrivateKey, path: str, passphrase: str | None = None):
    """Write the key as PKCS#8 PEM, encrypted at rest when a passphrase is given.
    Until an HSM is available this, plus the witness log, is the control."""
    enc = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    with open(path, "wb") as f:
        f.write(data)


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:12]


def public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class AuditLog:
    def __init__(self, path=":memory:", signing_key: Ed25519PrivateKey | None = None, checkpoint_every=1000):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS audit(
            seq INTEGER PRIMARY KEY, ts REAL, bo TEXT, action TEXT, record TEXT, prev TEXT, hash TEXT)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS checkpoints(seq INTEGER PRIMARY KEY, head TEXT, sig TEXT, kid TEXT)")
        self.lock = threading.RLock()
        self.key = signing_key or load_signing_key()
        self.pub = self.key.public_key()
        self.kid = key_id(self.pub)
        self.keyring = {self.kid: self.pub}     # every key that ever signed, by id
        self.checkpoint_every = checkpoint_every
        # The witness log is the copy of every signed head that leaves the building
        # (an auditor, SEBI, a public repository). Rewriting history then means
        # forging signatures and changing someone else's records too.
        self.witness_path = os.environ.get("AGENTSNAP_WITNESS")
        row = self.db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        self.seq, self.head = (row[0], row[1]) if row else (0, GENESIS)
        self.pending = []
        self.pending_cp = []

    def append(self, record: dict) -> tuple[int, str]:
        with self.lock:
            self.seq += 1
            rec = canon(record)
            hsh = hashlib.sha256((self.head + rec).encode()).hexdigest()
            self.pending.append((self.seq, record.get("ts"), record.get("bo"), record.get("action"), rec, self.head, hsh))
            self.head = hsh
            if self.seq % self.checkpoint_every == 0:
                self.pending_cp.append((self.seq, hsh, self._sign(self.seq, hsh), self.kid))
            if len(self.pending) >= 500:
                self.flush()
            return self.seq, hsh

    def _sign(self, seq, head):
        return base64.b64encode(self.key.sign(f"{seq}:{head}".encode())).decode()

    def checkpoint(self):
        """Sign the current head now (for example before a snapshot or at shutdown)."""
        with self.lock:
            if self.seq and not any(s == self.seq for s, *_ in self.pending_cp):
                self.pending_cp.append((self.seq, self.head, self._sign(self.seq, self.head), self.kid))
            self.flush()

    def rotate_key(self, new_key: Ed25519PrivateKey | None = None) -> str:
        """Sign the head with the old key, switch keys, record the rotation in the chain."""
        with self.lock:
            self.checkpoint()
            old = self.kid
            self.key = new_key or Ed25519PrivateKey.generate()
            self.pub = self.key.public_key()
            self.kid = key_id(self.pub)
            self.keyring[self.kid] = self.pub
            self.append({"ts": None, "bo": "-", "action": "key_rotation", "from": old, "to": self.kid, "public_key": self.public_key_pem()})
            self.checkpoint()
            return self.kid

    def flush(self):
        with self.lock:
            if self.pending:
                self.db.executemany("INSERT INTO audit VALUES (?,?,?,?,?,?,?)", self.pending)
                self.pending.clear()
            if self.pending_cp:
                self.db.executemany("INSERT OR REPLACE INTO checkpoints VALUES (?,?,?,?)", self.pending_cp)
                if self.witness_path:
                    with open(self.witness_path, "a", encoding="utf8") as f:
                        for s, hd, sg, kid in self.pending_cp:
                            f.write(canon({"seq": s, "head": hd, "sig": sg, "kid": kid}) + "\n")
                self.pending_cp.clear()
            self.db.commit()

    def verify_witness(self, lines) -> dict:
        """Check a published witness log against this database: every signed head
        must verify and must equal the chain's hash at that sequence number."""
        with self.lock:
            self.flush()
            hashes = dict(self.db.execute("SELECT seq, hash FROM audit"))
        n = 0
        for line in lines:
            w = json.loads(line)
            pub = self.keyring.get(w["kid"])
            if pub is None:
                return {"ok": False, "seq": w["seq"], "reason": f"unknown key {w['kid']}"}
            try:
                pub.verify(base64.b64decode(w["sig"]), f"{w['seq']}:{w['head']}".encode())
            except InvalidSignature:
                return {"ok": False, "seq": w["seq"], "reason": "witness signature invalid"}
            if hashes.get(w["seq"]) != w["head"]:
                return {"ok": False, "seq": w["seq"], "reason": "database differs from the published witness"}
            n += 1
        return {"ok": True, "witnessed": n}

    def verify(self, public_key: Ed25519PublicKey | None = None) -> dict:
        keyring = dict(self.keyring)
        if public_key is not None:
            keyring = {key_id(public_key): public_key}
        with self.lock:
            self.flush()
            cps = {s: (hd, sg, kid) for s, hd, sg, kid in self.db.execute("SELECT seq, head, sig, kid FROM checkpoints")}
            prev, n, signed = GENESIS, 0, 0
            for seq, rec, p, hsh in self.db.execute("SELECT seq, record, prev, hash FROM audit ORDER BY seq"):
                n += 1
                calc = hashlib.sha256((prev + rec).encode()).hexdigest()
                if p != prev or calc != hsh:
                    return {"ok": False, "checked": n, "first_bad_seq": seq, "reason": "hash chain broken", "head": self.head}
                if seq in cps:
                    head, sig, kid = cps[seq]
                    pub = keyring.get(kid)
                    if pub is None:
                        return {"ok": False, "checked": n, "first_bad_seq": seq, "reason": f"checkpoint signed by unknown key {kid}", "head": self.head}
                    try:
                        pub.verify(base64.b64decode(sig), f"{seq}:{head}".encode())
                    except InvalidSignature:
                        return {"ok": False, "checked": n, "first_bad_seq": seq, "reason": "checkpoint signature invalid", "head": self.head}
                    if head != hsh:
                        return {"ok": False, "checked": n, "first_bad_seq": seq, "reason": "chain differs from signed checkpoint", "head": self.head}
                    signed += 1
                prev = hsh
            return {"ok": True, "checked": n, "signed_checkpoints": signed, "head": prev}

    def tamper(self, seq: int, recompute=False) -> bool:
        """Demo only. Flip one record's action. With recompute=True also rewrite every
        later hash, the way an insider would; the signed checkpoints still catch it."""
        with self.lock:
            self.flush()
            row = self.db.execute("SELECT record FROM audit WHERE seq=?", (seq,)).fetchone()
            if not row:
                return False
            rec = json.loads(row[0])
            rec["action"] = "block" if rec.get("action") == "allow" else "allow"
            self.db.execute("UPDATE audit SET record=?, action=? WHERE seq=?", (canon(rec), rec["action"], seq))
            if recompute:
                prev = self.db.execute("SELECT prev FROM audit WHERE seq=?", (seq,)).fetchone()[0]
                for s, r in self.db.execute("SELECT seq, record FROM audit WHERE seq>=? ORDER BY seq", (seq,)).fetchall():
                    hh = hashlib.sha256((prev + r).encode()).hexdigest()
                    self.db.execute("UPDATE audit SET prev=?, hash=? WHERE seq=?", (prev, hh, s))
                    prev = hh
                self.head = prev
            self.db.commit()
            return True

    def tail(self, n=50):
        with self.lock:
            self.flush()
            rows = self.db.execute("SELECT seq, ts, bo, action, hash FROM audit ORDER BY seq DESC LIMIT ?", (n,)).fetchall()
            return [{"seq": s, "ts": t, "bo": b, "action": a, "hash": hh} for s, t, b, a, hh in rows]

    def public_key_pem(self):
        return public_pem(self.key)

    def close(self):
        """Flush, sign the final head, close. Called on graceful shutdown."""
        try:
            self.checkpoint()
            self.db.close()
        except sqlite3.ProgrammingError:
            pass  # already closed

    def __del__(self):
        try:
            self.db.close()
        except Exception:
            pass


class EventLog:
    """Append-only log of inputs (events and hold actions), in arrival order."""

    def __init__(self, db: sqlite3.Connection, lock):
        self.db, self.lock = db, lock
        self.db.execute("CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, kind TEXT, payload TEXT)")
        row = self.db.execute("SELECT MAX(seq) FROM events").fetchone()
        self.seq = row[0] or 0
        self.pending = []

    def append(self, kind: str, payload: dict) -> int:
        with self.lock:
            self.seq += 1
            self.pending.append((self.seq, kind, canon(payload)))
            if len(self.pending) >= 500:
                self.flush()
            return self.seq

    def flush(self):
        with self.lock:
            if self.pending:
                self.db.executemany("INSERT INTO events VALUES (?,?,?)", self.pending)
                self.pending.clear()
                self.db.commit()

    def purge_before(self, cutoff_ts: float, keep_after_seq: int = 0) -> int:
        """Retention: delete logged inputs older than the cutoff, but never ones the
        latest snapshot still needs for replay. Decisions stay in the audit chain."""
        self.flush()
        with self.lock:
            cur = self.db.execute("DELETE FROM events WHERE seq<=? AND json_extract(payload,'$.ts')<?", (keep_after_seq, cutoff_ts))
            self.db.commit()
            return cur.rowcount

    def for_bo(self, bo: str, limit=500):
        self.flush()
        rows = self.db.execute("SELECT seq, kind, payload FROM events WHERE json_extract(payload,'$.bo')=? ORDER BY seq DESC LIMIT ?", (bo, limit))
        return [{"seq": s, "kind": k, **json.loads(p)} for s, k, p in rows.fetchall()]

    def after(self, seq: int):
        self.flush()
        for s, kind, payload in self.db.execute("SELECT seq, kind, payload FROM events WHERE seq>? ORDER BY seq", (seq,)).fetchall():
            yield s, kind, json.loads(payload)
