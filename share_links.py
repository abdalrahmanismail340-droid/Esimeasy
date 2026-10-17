"""Share links: open the dialer without Google login, using the owner's
current eSIMEasy session.

Storage: a small SQLite file. On Railway it lives on a volume
(RAILWAY_VOLUME_MOUNT_PATH, e.g. /data) so links survive restarts and
redeploys. Without a volume it falls back to ./data (lost on redeploy).

Safeguards
- The URL carries only a random token (secrets.token_urlsafe(32)); never the
  sessionId or a phone number.
- Only sha256(token) is stored, so the database cannot recreate links.
- The owner's eSIMEasy session is stored encrypted (Fernet, key derived from
  SECRET_KEY) and keyed by the owner, so every link follows the owner's latest
  login automatically.
- Every request re-checks expiry and revocation.
- Tokens, sessionIds and passwords are never logged.
"""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

EXPIRY_CHOICES = {1: "ساعة", 24: "24 ساعة", 168: "7 أيام"}
DEFAULT_HOURS = 24
MAX_ACTIVE_LINKS = 20

_lock = threading.Lock()
_conn = None
_fernet = None
DB_PATH = ""


def _db_path():
    explicit = os.environ.get("LINKS_DB_PATH")
    if explicit:
        return explicit, True
    vol = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    if vol:
        return os.path.join(vol, "share_links.db"), True
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "share_links.db"), False


def init(secret_key):
    global _conn, _fernet, DB_PATH
    DB_PATH, persistent = _db_path()
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.executescript("""
        CREATE TABLE IF NOT EXISTS owners (
            owner_id TEXT PRIMARY KEY,
            esim_enc TEXT NOT NULL,
            phone_auth INTEGER NOT NULL DEFAULT 0,
            device_id TEXT,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS links (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            owner_id TEXT NOT NULL,
            label TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            last_used_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS links_owner ON links(owner_id);
        CREATE TABLE IF NOT EXISTS owner_settings (
            owner_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (owner_id, key)
        );
    """)
    key = base64.urlsafe_b64encode(hashlib.sha256(
        ("share-links:" + (secret_key or "")).encode()).digest())
    _fernet = Fernet(key)
    print(f"[share-links] storage={'persistent' if persistent else 'ephemeral (no volume - links lost on redeploy)'}", flush=True)


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _now():
    return int(time.time())


def _q(sql, args=()):
    with _lock:
        return _conn.execute(sql, args).fetchall()


def _exec(sql, args=()):
    with _lock:
        cur = _conn.execute(sql, args)
        return cur.rowcount


# ---------- owner session ----------
_ESIM_KEYS = ("sessionId", "remainCallPoint", "remainPoint", "appVersion")


def save_owner(owner_id, esim, phone_auth=None, device_id=None, create=False):
    """Store/refresh the owner's eSIMEasy session. With create=False only an
    existing row is updated (owners that have generated a link before)."""
    if not owner_id or not esim or not esim.get("sessionId"):
        return
    data = {k: esim.get(k) for k in _ESIM_KEYS}
    enc = _fernet.encrypt(json.dumps(data).encode()).decode()
    if create:
        _exec("""INSERT INTO owners(owner_id, esim_enc, phone_auth, device_id, updated_at)
                 VALUES(?,?,?,?,?)
                 ON CONFLICT(owner_id) DO UPDATE SET esim_enc=excluded.esim_enc,
                   phone_auth=MAX(owners.phone_auth, excluded.phone_auth),
                   device_id=COALESCE(excluded.device_id, owners.device_id),
                   updated_at=excluded.updated_at""",
              (owner_id, enc, int(bool(phone_auth)), device_id, _now()))
    else:
        _exec("""UPDATE owners SET esim_enc=?, updated_at=?,
                   phone_auth=CASE WHEN ? THEN 1 ELSE phone_auth END,
                   device_id=COALESCE(?, device_id)
                 WHERE owner_id=?""",
              (enc, _now(), int(bool(phone_auth)), device_id, owner_id))


def update_owner_balances(owner_id, coins, points):
    owner = get_owner(owner_id)
    if owner:
        esim = owner["esim"]
        esim["remainCallPoint"], esim["remainPoint"] = coins, points
        save_owner(owner_id, esim)


def get_owner(owner_id):
    rows = _q("SELECT * FROM owners WHERE owner_id=?", (owner_id,))
    if not rows:
        return None
    r = rows[0]
    try:
        esim = json.loads(_fernet.decrypt(r["esim_enc"].encode()))
    except (InvalidToken, ValueError):
        return None  # SECRET_KEY changed: links stop working until re-login
    return {"esim": esim, "phone_auth": bool(r["phone_auth"]), "device_id": r["device_id"]}


# ---------- links ----------
def create_link(owner_id, hours, label=""):
    hours = hours if hours in EXPIRY_CHOICES else DEFAULT_HOURS
    if count_active(owner_id) >= MAX_ACTIVE_LINKS:
        raise ValueError("too many active links")
    token = secrets.token_urlsafe(32)
    link_id = secrets.token_hex(6)
    now = _now()
    _exec("""INSERT INTO links(id, token_hash, owner_id, label, created_at, expires_at)
             VALUES(?,?,?,?,?,?)""",
          (link_id, _hash(token), owner_id, (label or "")[:40], now, now + hours * 3600))
    return token, {"id": link_id, "label": (label or "")[:40],
                   "created_at": now, "expires_at": now + hours * 3600}


def _row_status(r):
    if r is None:
        return "invalid"
    if r["revoked_at"]:
        return "revoked"
    if r["expires_at"] <= _now():
        return "expired"
    return "active"


def resolve_token(token):
    """-> (status, row). status: active / expired / revoked / invalid."""
    if not token or len(token) > 100:
        return "invalid", None
    rows = _q("SELECT * FROM links WHERE token_hash=?", (_hash(token),))
    r = rows[0] if rows else None
    return _row_status(r), r


def get_link(link_id):
    rows = _q("SELECT * FROM links WHERE id=?", (link_id,))
    r = rows[0] if rows else None
    return _row_status(r), r


def touch(link_id):
    _exec("UPDATE links SET last_used_at=? WHERE id=?", (_now(), link_id))


def count_active(owner_id):
    return _q("""SELECT COUNT(*) AS n FROM links WHERE owner_id=? AND revoked_at IS NULL
                 AND expires_at>?""", (owner_id, _now()))[0]["n"]


def list_active(owner_id):
    rows = _q("""SELECT id, label, created_at, expires_at, last_used_at FROM links
                 WHERE owner_id=? AND revoked_at IS NULL AND expires_at>?
                 ORDER BY created_at DESC""", (owner_id, _now()))
    return [dict(r) for r in rows]


def revoke(owner_id, link_id):
    return _exec("""UPDATE links SET revoked_at=? WHERE id=? AND owner_id=?
                    AND revoked_at IS NULL""", (_now(), link_id, owner_id)) > 0


def revoke_all(owner_id):
    return _exec("""UPDATE links SET revoked_at=? WHERE owner_id=? AND revoked_at IS NULL""",
                 (_now(), owner_id))


def purge_old(days=30):
    _exec("DELETE FROM links WHERE expires_at<? OR (revoked_at IS NOT NULL AND revoked_at<?)",
          (_now() - days * 86400, _now() - days * 86400))


# ---------- per-owner settings (recording toggle, email for the Telegram bot) ----------
def get_setting(owner_id, key, default=None):
    rows = _q("SELECT value FROM owner_settings WHERE owner_id=? AND key=?", (owner_id, key))
    return rows[0]["value"] if rows else default


def set_setting(owner_id, key, value):
    _exec("""INSERT INTO owner_settings(owner_id, key, value) VALUES(?,?,?)
             ON CONFLICT(owner_id, key) DO UPDATE SET value=excluded.value""",
          (owner_id, key, None if value is None else str(value)))


def find_owner_by_setting(key, value):
    rows = _q("SELECT owner_id FROM owner_settings WHERE key=? AND lower(value)=lower(?)", (key, value))
    return rows[0]["owner_id"] if rows else None


def latest_owner():
    rows = _q("SELECT owner_id FROM owners ORDER BY updated_at DESC LIMIT 1")
    return rows[0]["owner_id"] if rows else None
