import os
import uuid
import base64
import threading
from datetime import timedelta
from flask import Flask, redirect, url_for, session, render_template, request
from flask_sock import Sock
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import requests
import websocket as ws_client
from rates import RATES

ESIMEASY_LOGIN_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/v4/user/login"
ESIMEASY_CALL_REQ_URL = "https://esimapi.esimeasy.co.kr:8444/baycscsd/outbound/dtls/call/req"
# AES key/IV the official app uses to encrypt the userId before login
# (ww.u0 in the decompiled APK: AES/CBC/PKCS5Padding)
ESIMEASY_AES_KEY = b"Ykuf2gLd95W?Zfsd"


def esim_encrypt_user_id(plain):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(ESIMEASY_AES_KEY),
                    modes.CBC(ESIMEASY_AES_KEY))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode("ascii")


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
# Keep the login alive for 30 days instead of forgetting it when the browser closes
app.permanent_session_lifetime = timedelta(days=30)
# Railway terminates TLS at its edge proxy and forwards plain HTTP;
# without this, url_for(_external=True) builds an http:// callback URL
# and Google rejects the login with redirect_uri_mismatch.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

sock = Sock(app)


@sock.route("/ws-echo")
def ws_echo(ws):
    """Simple echo to test if WebSockets work at all on this deploy."""
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            ws.send("echo:" + str(msg))
    except Exception:
        pass


@sock.route("/ws-proxy")
def ws_proxy(ws):
    """Relay browser wss:// <-> eSIMEasy ws:// (browser blocks plain ws from HTTPS)."""
    stop = threading.Event()
    DIAG = True  # temporary: step-by-step diagnostics

    def diag(msg):
        if DIAG:
            try:
                ws.send("ERROR:diag:" + msg)
            except Exception:
                pass

    def send_error_and_close(reason):
        """Tell the browser exactly which leg failed before closing."""
        try:
            ws.send("ERROR:" + reason)
        except Exception:
            pass
        try:
            ws.close()
        except Exception:
            pass

    try:
        diag("start")
        if "user" not in session:
            send_error_and_close("no-login-session")
            return
        diag("session-ok")
        target_host = request.args.get("host", "")
        target_port = request.args.get("port", "")
        if not target_host or not target_port:
            send_error_and_close("missing-host-port")
            return
        diag(f"target:{target_host}:{target_port}")
        target_url = f"ws://{target_host}:{target_port}/ws"
        try:
            backend = ws_client.create_connection(
                target_url, subprotocols=["sip"], timeout=10)
            backend.settimeout(None)  # blocking recv after connect
        except Exception as e:
            send_error_and_close(f"backend-connect-failed:{type(e).__name__}:{str(e)[:80]}")
            return
        diag("backend-ok")
    except Exception as e:
        try:
            ws.send(f"ERROR:proxy-crashed:{type(e).__name__}:{str(e)[:80]}")
        except Exception:
            pass
        try:
            ws.close()
        except Exception:
            pass
        return

    def backend_to_browser():
        try:
            while not stop.is_set():
                try:
                    msg = backend.recv()  # blocking; raises/None on close
                except Exception:
                    break
                if msg is None:
                    break
                try:
                    ws.send(msg)
                except Exception:
                    break
        finally:
            stop.set()

    t = threading.Thread(target=backend_to_browser, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            try:
                msg = ws.receive()  # blocking; None/raises on close
            except Exception:
                break
            if msg is None:
                break
            try:
                backend.send(msg)
            except Exception:
                break
    finally:
        stop.set()
        try:
            backend.close()
        except Exception:
            pass
        try:
            ws.close()
        except Exception:
            pass


@app.route("/")
def index():
    user = session.get("user")
    if user:
        return render_template("dashboard.html", user=user,
                               esim=session.get("esimeasy"))
    return render_template("login.html")


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    token = google.authorize_access_token()
    userinfo = token.get("userinfo")
    if userinfo:
        session.permanent = True
        google_id = userinfo.get("sub", "")
        email = userinfo.get("email", "")
        session["user"] = {
            "name": userinfo.get("name"),
            "email": email,
            "picture": userinfo.get("picture"),
            "google_id": google_id,
        }
        # Auto-login to eSIMEasy with verified Google user ID + Email fallback
        if google_id or email:
            session["esimeasy"] = esimeasy_login(google_id, email)
    return redirect(url_for("index"))


def esimeasy_login(google_user_id, email=""):
    """Log into eSIMEasy's backend using the Google user ID (with Email & format fallbacks).

    Returns dict with sessionId / remainCallPoint on success, else error dict.
    """
    device_id = session.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
        session["device_id"] = device_id

    headers = {
        "User-Agent": "okhttp/4.9.3",
        "Accept": "application/json",
    }

    # Try encrypted Google ID first, then encrypted Email, then plain IDs as fallback
    candidates = []
    if google_user_id:
        candidates.append(esim_encrypt_user_id(google_user_id))
    if email:
        candidates.append(esim_encrypt_user_id(email))
        if "@" in email:
            candidates.append(esim_encrypt_user_id(email.split("@")[0]))
    if google_user_id:
        candidates.append(google_user_id)
    if email:
        candidates.append(email)

    last_data = {}
    last_err = None

    for enc_id in candidates:
        for use_json in (True, False):
            payload = {
                "userId": enc_id,
                "paramUserId": enc_id,
                "authenType": "UAT0002",
                "paramAuthenType": "UAT0002",
                "deviceOs": "AT0001",
                "deviceId": device_id,
                "deviceModel": "SM-A366B",
                "deviceOsVersion": "14",
                "deviceOsLanguage": "en",
                "pushToken": "",
                "installRootId": "",
                "isTest": False if use_json else "false",
                "appVersion": "3.0.0",
                "languageCd": "en",
            }
            try:
                if use_json:
                    r = requests.post(ESIMEASY_LOGIN_URL, json=payload, headers=headers, timeout=15)
                else:
                    r = requests.post(ESIMEASY_LOGIN_URL, data=payload, headers=headers, timeout=15)
                data = r.json()
            except Exception as e:
                last_err = str(e)
                continue

            if not isinstance(data, dict):
                continue

            last_data = data
            if data.get("sessionId"):
                try:
                    balance = float(data.get("remainCallPoint") or 0)
                except (TypeError, ValueError):
                    balance = 0
                return {
                    "sessionId": data.get("sessionId"),
                    "remainCallPoint": balance,
                    "memberId": data.get("memberId", ""),
                    "email": data.get("email", ""),
                }

    if not last_data and last_err:
        return {"_error": f"[b3] connection: {last_err}"}

    ret_code = last_data.get("retCode")
    ret_msg = last_data.get("retMsg") or last_data.get("message") or ""
    return {
        "_error": f"[b3] retCode={ret_code} {ret_msg}".strip(),
        "_retCode": ret_code,
        "_raw": str(last_data)[:250],
    }


@app.route("/dialer")
def dialer():
    if "user" not in session:
        return redirect(url_for("index"))
    esim = session.get("esimeasy") or {}
    if not esim.get("sessionId"):
        return redirect(url_for("index"))
    return render_template("dialer.html", user=session["user"],
                           balance=esim.get("remainCallPoint", 0))


@app.route("/api/call/setup", methods=["POST"])
def api_call_setup():
    """Call eSIMEasy call/req and return WebRTC/SIP credentials for the browser dialer."""
    if "user" not in session:
        return {"error": "not logged in"}, 401
    esim = session.get("esimeasy") or {}
    session_id = esim.get("sessionId")
    if not session_id:
        return {"error": "eSIMEasy not connected"}, 400
    body = request.get_json(force=True, silent=True) or {}
    number = "".join(c for c in str(body.get("number", "")) if c.isdigit())
    country_code = "".join(c for c in str(body.get("country_code", "")) if c.isdigit())
    if not number:
        return {"error": "missing number"}, 400
    # dialString = countryNum + number with leading 0 stripped (like the app)
    dial_number = number.lstrip("0")
    unique_id = uuid.uuid4().hex
    payload = {
        "sessionId": session_id,
        "paramUniqueId": unique_id,
        "nationalUniqueId": unique_id,
        "paramNationalId": country_code,
        "nationalId": country_code,
        "paramPhoneId": dial_number,
        "phoneId": dial_number,
        "networkTp": "NT0001",
        "appCd": "ACT0060",
        "appVersion": "3.0.0",
        "languageCd": "en",
    }
    try:
        r = requests.post(ESIMEASY_CALL_REQ_URL, json=payload,
                          headers={"User-Agent": "okhttp/4.9.3"}, timeout=20)
        data = r.json()
    except Exception as e:
        return {"error": f"call setup failed: {e}"}, 502
    if not isinstance(data, dict) or not data.get("webrtcId"):
        return {"error": "call setup rejected",
                "retCode": data.get("retCode") if isinstance(data, dict) else None,
                "raw": str(data)[:300]}, 502
    # Pass through only what the browser dialer needs
    return {
        "callSequence": data.get("callSequence"),
        "webrtcAddr": data.get("webrtcAddr"),
        "webrtcPort": data.get("webrtcPort"),
        "webrtcId": data.get("webrtcId"),
        "webrtcPwd": data.get("webrtcPwd"),
        "stunAddr": data.get("stunAddr"),
        "turnAddr": data.get("turnAddr") or data.get("turnAddrIpV4"),
        "turnId": data.get("turnId"),
        "turnPwd": data.get("turnPwd"),
        "isDtls": data.get("isDtls"),
        "isTls": data.get("isTls"),
        "isTurn": data.get("isTurn"),
        "codecSpec": data.get("codecSpec"),
        "dialString": country_code + dial_number,
        "uniqueId": unique_id,
    }


@app.route("/api/prefix/<code>")
def api_prefix(code):
    """Return country name + mobile rate for a dial code (used by the dialer)."""
    if "user" not in session:
        return {"error": "not logged in"}, 401
    entries = RATES.get(code)
    if not entries:
        return {"error": "unknown"}, 404
    name, rate = entries[0]
    return {"code": code, "name": name, "rate": rate}


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("esimeasy", None)
    return redirect(url_for("index"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/rates", methods=["GET", "POST"])
def rates():
    if "user" not in session:
        return redirect(url_for("index"))
    esim = session.get("esimeasy") or {}
    auto_balance = esim.get("remainCallPoint")
    # Auto balance from eSIMEasy account when available, else manual (remembered).
    balance = auto_balance if auto_balance else session.get("balance", 10000)
    balance_auto = bool(auto_balance)
    result = None
    if request.method == "POST":
        raw = request.form.get("code", "").strip()
        query = raw.lower().lstrip("+").replace(" ", "").replace("-", "")
        manual = request.form.get("balance", "").strip()
        if manual:
            try:
                balance = int(manual)
                balance_auto = False
            except (ValueError, TypeError):
                pass
        session["balance"] = balance
        matches = []
        detected_from_number = None
        for code, entries in RATES.items():
            for name, rate in entries:
                if query and (query == code or query in name.lower()):
                    minutes = round(balance / rate, 1) if rate else 0
                    matches.append({"code": code, "name": name, "rate": rate,
                                    "minutes": minutes})
        # Phone-number prefix detection: longest dial code matching the start
        if not matches and query.isdigit():
            for length in range(min(len(query), 6), 0, -1):
                prefix = query[:length]
                if prefix in RATES:
                    detected_from_number = prefix
                    for name, rate in RATES[prefix]:
                        minutes = round(balance / rate, 1) if rate else 0
                        matches.append({"code": prefix, "name": name,
                                        "rate": rate, "minutes": minutes})
                    break
        result = {"query": raw, "balance": balance, "matches": matches,
                  "detected_from_number": detected_from_number,
                  "balance_auto": balance_auto}
    return render_template("rates.html", result=result, balance=balance,
                           balance_auto=balance_auto)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
