from gevent import monkey
monkey.patch_all()

import os
import ssl
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
from iso3_codes import CALLING_CODE_TO_ISO3, RATE_PREFIX_ALIASES
from retcodes import message_for, is_definitive

ESIMEASY_LOGIN_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/v4/user/login"
ESIMEASY_CALL_REQ_URL = "https://esimapi.esimeasy.co.kr:8444/baycscsd/outbound/dtls/call/req"
ESIMEASY_AUTH_REQ_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/user/authen/whatsapp/req"
ESIMEASY_AUTH_RES_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/user/authen/whatsapp/res"
ESIMEASY_SESSION_INFO_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/session/info/v1"
# Current official app version (APK v1.8.8, versionCode 132). LEGACY_APP_VERSION is
# what this project sent before and is known to work; used only as a fallback.
APP_VERSION = "1.8.8"
LEGACY_APP_VERSION = "3.0.0"
NETWORK_TYPES = {"NT0000", "NT0001", "NT0003"}  # unknown / wifi / cellular (MakeOutbound)
# AES key/IV the official app uses to encrypt the userId before login
ESIMEASY_AES_KEY = b"Ykuf2gLd95W?Zfsd"

# Fake token & install root constants to spoof the official Android App fingerprint
SPOOFED_PUSH_TOKEN = "fcm_token_fake_dummy_string_to_spoof_android_app_123456789"
SPOOFED_INSTALL_ROOT = "mock_install_root_id_fixed_string"


def esim_encrypt_user_id(plain):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(ESIMEASY_AES_KEY),
                    modes.CBC(ESIMEASY_AES_KEY))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode("ascii")


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "dev-secret-change-me"
if app.secret_key == "dev-secret-change-me":
    print("[warn] SECRET_KEY is not set - using an insecure dev key. Set SECRET_KEY in Railway.", flush=True)
app.permanent_session_lifetime = timedelta(days=30)
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
BROWSER_KEEPALIVE = "__ka__"


@sock.route("/ws-echo")
def ws_echo(ws):
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
    """Relay browser wss:// <-> eSIMEasy ws:// or wss:// with Nginx 400 bypass."""
    stop = threading.Event()

    def diag(msg):
        try:
            ws.send("ERROR:diag:" + msg)
        except Exception:
            pass

    def send_error_and_close(reason):
        try:
            ws.send("ERROR:" + reason)
        except Exception:
            pass
        try:
            ws.close()
        except Exception:
            pass

    try:
        if "user" not in session:
            send_error_and_close("no-login-session")
            return

        target_host = request.args.get("host", "").strip()
        target_port = request.args.get("port", "").strip()
        is_tls = request.args.get("tls", "0").lower() in ("1", "true", "y", "yes")

        if not target_host or not target_port:
            send_error_and_close("missing-host-port")
            return

        target_host = (
            target_host.replace("ws://", "")
            .replace("wss://", "")
            .replace("http://", "")
            .replace("https://", "")
            .split("/")[0]
            .split(":")[0]
        )

        diag(f"connecting:{target_host}:{target_port}")

        schemes = ["wss", "ws"] if is_tls else ["ws", "wss"]
        paths = ["/ws", "/", "/wss"]

        header_variants = [
            (True, [f"Host: {target_host}", "User-Agent: okhttp/4.9.3"]),
            (True, ["User-Agent: okhttp/4.9.3"]),
            (False, ["User-Agent: okhttp/4.9.3"]),
        ]

        backend = None
        used_scheme = "ws"
        errors_log = []
        wss_errors = []

        for scheme in schemes:
            for path in paths:
                for suppress_orig, custom_headers in header_variants:
                    url = f"{scheme}://{target_host}:{target_port}{path}"
                    try:
                        sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False} if scheme == "wss" else None
                        backend = ws_client.create_connection(
                            url,
                            subprotocols=["sip"],
                            header=custom_headers,
                            suppress_origin=suppress_orig,
                            sslopt=sslopt,
                            timeout=5,
                        )
                        backend.settimeout(None)
                        used_scheme = scheme
                        break
                    except Exception as e:
                        err_short = str(e).replace("\n", " ")[:60]
                        errors_log.append(f"{scheme}{path}(sup={int(suppress_orig)}):{err_short}")
                        if scheme == "wss":
                            wss_errors.append(f"{path}(sup={int(suppress_orig)}):{err_short}")
                        continue
                if backend:
                    break
            if backend:
                break
            # السيرفر طالب SIPS (isTls=Y): الـ WS العادي هياخد 480 "SIPS Required" مؤكد
            # فممنوع الـ fallback الصامت لـ ws — لازم نعرف ليه الـ wss فشل
            if is_tls and scheme == "wss" and not backend:
                diag("wss-failed:" + " | ".join(wss_errors[:6]))
                send_error_and_close("backend-tls-failed:" + " | ".join(wss_errors[:3]))
                return

        if not backend:
            send_error_and_close("backend-connect-failed:" + " | ".join(errors_log[:3]))
            return

        diag(f"backend-ok:{used_scheme}")

    except Exception as e:
        send_error_and_close(f"proxy-crashed:{type(e).__name__}:{str(e)[:80]}")
        return

    def backend_to_browser():
        try:
            while not stop.is_set():
                try:
                    msg = backend.recv()
                except Exception:
                    break
                if msg is None or msg == "":
                    break
                try:
                    ws.send(msg)
                except Exception:
                    break
        finally:
            stop.set()

    def backend_pinger():
        # WebSocket-level ping to the SIP server every 15s so idle connections
        # are not dropped (instead of injecting SIP OPTIONS into the dialog).
        while not stop.wait(15):
            try:
                backend.ping("ka")
            except Exception:
                stop.set()
                break

    t = threading.Thread(target=backend_to_browser, daemon=True)
    t.start()
    threading.Thread(target=backend_pinger, daemon=True).start()
    try:
        while not stop.is_set():
            try:
                msg = ws.receive()
            except Exception:
                break
            if msg is None:
                break
            if msg == BROWSER_KEEPALIVE:
                # browser <-> proxy keepalive; never forwarded to the SIP server
                continue
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
        if google_id or email:
            session["esimeasy"] = esimeasy_login(google_id, email)
    return redirect(url_for("index"))


def _num(v):
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def esimeasy_login(google_user_id, email=""):
    device_id = session.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
        session["device_id"] = device_id

    headers = {
        "User-Agent": "okhttp/4.9.3",
        "Accept": "application/json",
    }

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

    # Same identity order as before (the official app sends AES(google id) only);
    # each identity is tried with the current app version first, then the legacy one,
    # before moving on, so a version problem can never switch us to another account.
    attempts = [(enc_id, ver, use_json)
                for enc_id in candidates
                for ver in (APP_VERSION, LEGACY_APP_VERSION)
                for use_json in (True, False)]
    for enc_id, app_version, use_json in attempts:
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
                "pushToken": SPOOFED_PUSH_TOKEN,
                "installRootId": SPOOFED_INSTALL_ROOT,
                "isTest": False if use_json else "false",
                "appVersion": app_version,
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
                if app_version != APP_VERSION:
                    print(f"[login] succeeded only with legacy appVersion {app_version}", flush=True)
                return {
                    "sessionId": data.get("sessionId"),
                    "remainCallPoint": _num(data.get("remainCallPoint")),
                    "remainPoint": _num(data.get("remainPoint")),
                    "appVersion": app_version,
                    "memberId": data.get("memberId", ""),
                    "email": data.get("email", ""),
                }

    if not last_data and last_err:
        return {"_error": f"[b3] connection: {last_err}"}

    ret_code = last_data.get("retCode")
    ret_msg = last_data.get("retMsg") or last_data.get("message") or ""
    print(f"[login REJECTED] retCode={ret_code} retMsg={ret_msg!r}", flush=True)
    return {
        "_error": f"[b3] retCode={ret_code} {ret_msg}".strip(),
        "_message": message_for(ret_code),
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
    countries = sorted(
        ({"code": code, "name": name, "rate": rate}
         for code, entries in RATES.items() for name, rate in entries[:1]),
        key=lambda c: c["name"])
    return render_template("dialer.html", user=session["user"],
                           balance=esim.get("remainCallPoint", 0),
                           points=esim.get("remainPoint"),
                           countries=countries,
                           phone_authenticated=bool(session.get("phone_authenticated")))


@app.route("/api/call/setup", methods=["POST"])
def api_call_setup():
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

    dial_number = number.lstrip("0")
    # Some rate prefixes (e.g. 1907 Alaska, 1808 Hawaii, 1787/1939 Puerto Rico)
    # are not country codes in the official app's table: they are dialled as
    # country "1" with the area code kept as part of the national number.
    alias = RATE_PREFIX_ALIASES.get(country_code)
    if alias:
        dial_number = country_code[len(alias):] + dial_number
        country_code = alias
    # التطبيق الأصلي بيبعت كود الدولة بنظام ISO3 (زي "EGY" لمصر، "USA" لأمريكا)
    # في paramUniqueId/nationalUniqueId — مش UUID عشوائي زي ما كنا باعتين.
    # الجدول ده مستخرج من tt.smali في الـ APK الرسمي.
    unique_id = CALLING_CODE_TO_ISO3.get(country_code)
    if not unique_id:
        # كود دولة مش موجود في الجدول (نادر) — fallback لمنع كراش، لكن ده
        # هيفشل زي قبل كده لو السيرفر فعلاً بيتحقق من القيمة دي.
        unique_id = uuid.uuid4().hex
    network_tp = str(body.get("networkTp", "")).strip().upper()
    if network_tp not in NETWORK_TYPES:
        network_tp = "NT0001"  # Wi-Fi: what the working requests used

    # Exactly the fields the official app sends (MakeOutbound, APK v1.8.8).
    payload = {
        "paramUniqueId": unique_id,
        "paramNationalId": country_code,
        "paramPhoneId": dial_number,
        "sessionId": session_id,
        "nationalUniqueId": unique_id,
        "nationalId": country_code,
        "phoneId": dial_number,
        "networkTp": network_tp,
        "appCd": "ACT0060",
        "appVersion": APP_VERSION,
        "languageCd": "en",
    }
    # Previous request shape (legacy appVersion + device/push fields). It got
    # retCode=1 on 2026-10-17 03:27 Cairo, so it is kept as a one-time fallback
    # when the app-exact request is rejected for a non-account reason.
    device_id = session.get("device_id") or str(uuid.uuid4())
    legacy_payload = dict(payload, networkTp="NT0001", appVersion=LEGACY_APP_VERSION,
                          deviceOs="AT0001", deviceId=device_id, deviceModel="SM-A366B",
                          deviceOsVersion="14", pushToken=SPOOFED_PUSH_TOKEN,
                          installRootId=SPOOFED_INSTALL_ROOT)

    def _post(p):
        r = requests.post(ESIMEASY_CALL_REQ_URL, json=p,
                          headers={"User-Agent": "okhttp/4.9.3"}, timeout=20)
        return r.json()

    def _ok(d):
        return isinstance(d, dict) and bool(d.get("webrtcId"))

    def _code_msg(d):
        d = d if isinstance(d, dict) else {}
        return d.get("retCode"), (d.get("retMsg") or d.get("message") or "")

    try:
        data = _post(payload)
    except Exception as e:
        return {"error": f"call setup failed: {e}"}, 502
    used = "app"
    if not _ok(data):
        code, msg = _code_msg(data)
        # rejection logging: code + message only
        print(f"[call/req REJECTED] retCode={code} retMsg={msg!r}", flush=True)
        if not is_definitive(code):
            try:
                legacy = _post(legacy_payload)
            except Exception as e:
                legacy = None
                print(f"[call/req legacy fallback failed] {type(e).__name__}", flush=True)
            if _ok(legacy):
                data, used = legacy, "legacy"
            elif legacy is not None:
                lcode, lmsg = _code_msg(legacy)
                print(f"[call/req REJECTED legacy] retCode={lcode} retMsg={lmsg!r}", flush=True)
    if not _ok(data):
        code, msg = _code_msg(data)
        return {"error": "call setup rejected",
                "retCode": code,
                "retMsg": msg,
                "message": message_for(code, msg),
                "coins": esim.get("remainCallPoint"),
                "points": esim.get("remainPoint")}, 502

    # Log only non-secret diagnostics (never sessionId / webrtcPwd / turnPwd).
    print(f"[call/req] retCode={data.get('retCode')} via={used} callSequence={data.get('callSequence')} "
          f"country_code={country_code} uniqueId={unique_id} networkTp={network_tp} "
          f"isTls={data.get('isTls')} isDtls={data.get('isDtls')} isTurn={data.get('isTurn')} "
          f"fields={sorted(data.keys())}", flush=True)

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
        # الاكتشاف الأهم: الـ From display name في SIP INVITE الحقيقي مش uniqueId
        # ولا ISO3 — هو sessionId بتاع تسجيل الدخول نفسه (اتأكد من smali:
        # Lbn4;->n بيتحط من ResultLogin.getSessionId()/ResultUserJoin.getSessionId()
        # في wn1.smali و g64.smali). ده اللي لازم يتبعت في الـ From، مش uniqueId.
        "sipIdentity": session_id,
        # كل الحقول الراجعة من السيرفر من غير فلترة — عشان نشوف أي حاجة ناقصة
        # في الريسبونس من غير ما نفتح Railway logs كل مرة.
        "rawFields": list(data.keys()),
        "coins": esim.get("remainCallPoint"),
        "points": esim.get("remainPoint"),
    }


@app.route("/api/prefix/<code>")
def api_prefix(code):
    if "user" not in session:
        return {"error": "not logged in"}, 401
    entries = RATES.get(code)
    if not entries:
        return {"error": "unknown"}, 404
    name, rate = entries[0]
    return {"code": code, "name": name, "rate": rate}


def _esimeasy_auth_headers():
    return {"User-Agent": "okhttp/4.9.3", "Accept": "application/json"}


@app.route("/api/phone-auth/req", methods=["POST"])
def api_phone_auth_req():
    """Request WhatsApp OTP for phone authentication (mandatory before calls)."""
    if "user" not in session or "esimeasy" not in session:
        return {"error": "not logged in"}, 401
    body = request.get_json(force=True, silent=True) or {}
    national_id = str(body.get("nationalId", "")).strip()
    phone_id = str(body.get("phoneId", "")).strip().lstrip("0")
    if not national_id or not phone_id:
        return {"error": "nationalId and phoneId required"}, 400
    alias = RATE_PREFIX_ALIASES.get(national_id)
    if alias:
        phone_id = national_id[len(alias):] + phone_id
        national_id = alias
    esim = session["esimeasy"]
    device_id = session.get("device_id") or str(uuid.uuid4())
    session["device_id"] = device_id
    payload = {
        "sessionId": esim.get("sessionId", ""),
        "deviceId": device_id,
        "nationalId": national_id,
        "phoneId": phone_id,
        "appVersion": "3.0.0",
        "languageCd": "en",
    }
    try:
        r = requests.post(ESIMEASY_AUTH_REQ_URL, json=payload,
                          headers=_esimeasy_auth_headers(), timeout=15)
        data = r.json()
    except Exception as e:
        return {"error": f"request failed: {e}"}, 502
    # remember for the verify step
    session["phone_auth_pending"] = {"nationalId": national_id, "phoneId": phone_id,
                                     "seqNo": data.get("seqNo", "")}
    return {"retCode": data.get("retCode"), "seqNo": data.get("seqNo", ""),
            "retryCount": data.get("retryCount", 0),
            "message": message_for(data.get("retCode"), data.get("retMsg") or ""),
            "raw": str(data)[:300]}


@app.route("/api/phone-auth/res", methods=["POST"])
def api_phone_auth_res():
    """Submit WhatsApp OTP to complete phone authentication."""
    if "user" not in session or "esimeasy" not in session:
        return {"error": "not logged in"}, 401
    body = request.get_json(force=True, silent=True) or {}
    pending = session.get("phone_auth_pending") or {}
    national_id = str(body.get("nationalId") or pending.get("nationalId", "")).strip()
    phone_id = str(body.get("phoneId") or pending.get("phoneId", "")).strip().lstrip("0")
    seq_no = str(body.get("seqNo") or pending.get("seqNo", "")).strip()
    authen_number = str(body.get("authenNumber", "")).strip()
    if not (national_id and phone_id and authen_number):
        return {"error": "nationalId, phoneId and authenNumber required"}, 400
    esim = session["esimeasy"]
    device_id = session.get("device_id") or str(uuid.uuid4())
    session["device_id"] = device_id
    payload = {
        "sessionId": esim.get("sessionId", ""),
        "deviceId": device_id,
        "nationalId": national_id,
        "phoneId": phone_id,
        "seqNo": seq_no,
        "authenNumber": authen_number,
        "appVersion": "3.0.0",
        "languageCd": "en",
    }
    try:
        r = requests.post(ESIMEASY_AUTH_RES_URL, json=payload,
                          headers=_esimeasy_auth_headers(), timeout=15)
        data = r.json()
    except Exception as e:
        return {"error": f"request failed: {e}"}, 502
    ok = str(data.get("retCode", "")) in ("0", "200", "1")
    if ok:
        session["phone_authenticated"] = True
        session.pop("phone_auth_pending", None)
    return {"retCode": data.get("retCode"), "ok": ok,
            "message": message_for(data.get("retCode"), data.get("retMsg") or ""),
            "raw": str(data)[:300]}


@app.route("/api/debug/session")
def api_debug_session():
    """تشخيص سريع: هل الحساب موثّق فعلاً؟ هل فيه session_id؟ من غير ما تجرب مكالمة."""
    if "user" not in session:
        return {"loggedIn": False}
    esim = session.get("esimeasy") or {}
    return {
        "loggedIn": True,
        "hasSessionId": bool(esim.get("sessionId")),
        "deviceId": session.get("device_id"),
        "phoneAuthenticated": bool(session.get("phone_authenticated")),
        "phoneAuthPending": session.get("phone_auth_pending"),
        "balance": esim.get("remainCallPoint"),
    }


@app.route("/api/debug/ip")
def api_debug_ip():
    """يرجع الـ outbound IP بتاع السيرفر (عشان نقارنه بـ IP الموبايل)."""
    if "user" not in session:
        return {"error": "not logged in"}, 401
    try:
        r = requests.get("https://ifconfig.me/ip", timeout=10)
        return {"outbound_ip": r.text.strip()}
    except Exception as e:
        return {"error": str(e)}, 502


@app.route("/ws-monitor")
def ws_monitor():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("ws_monitor.html")


def _relogin(keep_on_failure=False):
    user = session.get("user") or {}
    result = esimeasy_login(user.get("google_id", ""), user.get("email", ""))
    current = session.get("esimeasy") or {}
    # a failed balance refresh must not wipe a working eSIMEasy session
    if result.get("sessionId") or not (keep_on_failure and current.get("sessionId")):
        session["esimeasy"] = result
    return result


@app.route("/esim/retry", methods=["POST"])
def esim_retry():
    """Retry the eSIMEasy login without logging out of Google."""
    if "user" not in session:
        return redirect(url_for("index"))
    _relogin()
    return redirect(url_for("index"))


def _session_info(session_id):
    """session/info/v1 (same request as the official app's MakeSessionInfo).
    Returns the parsed dict on retCode 1, else None."""
    payload = {
        "sessionId": session_id,
        "isPushOn": True,
        "pushToken": SPOOFED_PUSH_TOKEN,
        "deviceOs": "AT0001",
        "installRootId": SPOOFED_INSTALL_ROOT,
        "isTest": False,
        "appVersion": APP_VERSION,
        "languageCd": "en",
    }
    try:
        r = requests.post(ESIMEASY_SESSION_INFO_URL, json=payload,
                          headers={"User-Agent": "okhttp/4.9.3", "Accept": "application/json"},
                          timeout=15)
        data = r.json()
    except Exception as e:
        print(f"[session/info] failed: {type(e).__name__}", flush=True)
        return None
    if isinstance(data, dict) and str(data.get("retCode")) == "1":
        return data
    d = data if isinstance(data, dict) else {}
    print(f"[session/info REJECTED] retCode={d.get('retCode')} "
          f"retMsg={(d.get('retMsg') or d.get('message') or '')!r}", flush=True)
    return None


@app.route("/api/esim/refresh", methods=["POST"])
def api_esim_refresh():
    """Fresh balances: Easy Coins (C, remainCallPoint - pays for calls) and
    Easy Points (P, remainPoint). Uses session/info/v1; re-logs in only if the
    session is no longer valid."""
    if "user" not in session:
        return {"error": "not logged in"}, 401
    esim = dict(session.get("esimeasy") or {})
    info = _session_info(esim["sessionId"]) if esim.get("sessionId") else None
    if info is not None:
        esim["remainCallPoint"] = _num(info.get("remainCallPoint"))
        esim["remainPoint"] = _num(info.get("remainPoint"))
        session["esimeasy"] = esim
        source = "session"
    else:
        esim = _relogin(keep_on_failure=True)
        if not esim.get("sessionId"):
            return {"error": esim.get("_message") or esim.get("_error", "login failed")}, 502
        source = "login"
    return {"coins": esim.get("remainCallPoint", 0), "points": esim.get("remainPoint", 0),
            "balance": esim.get("remainCallPoint", 0), "source": source}


@app.route("/logout")
def logout():
    # keep device_id so the account keeps seeing the same "device"
    for key in ("user", "esimeasy", "phone_authenticated", "phone_auth_pending", "balance"):
        session.pop(key, None)
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
