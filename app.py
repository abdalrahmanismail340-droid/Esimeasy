from gevent import monkey
monkey.patch_all()
import gevent

import os
import ssl
import uuid
import base64
import threading
from datetime import timedelta
from flask import Flask, redirect, url_for, session, render_template, request, g
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
import share_links
import telegram_bot

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
share_links.init(app.secret_key)
try:
    share_links.purge_old()
except Exception as _e:
    print(f"[share-links] purge failed: {type(_e).__name__}", flush=True)
telegram_bot.start()
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
        ctx = _ctx()
        if not ctx:
            send_error_and_close("no-login-session")
            return
        # Share-link browsers never see the owner's sessionId: they send a
        # placeholder in the SIP From display name and it is swapped here.
        sip_secret = (ctx.get("esim") or {}).get("sessionId") if ctx["mode"] == "link" else None

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
                if sip_secret and isinstance(msg, str):
                    msg = msg.replace(sip_secret, SIP_ID_PLACEHOLDER)
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
            if sip_secret and isinstance(msg, str):
                msg = msg.replace(SIP_ID_PLACEHOLDER, sip_secret)
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


SIP_ID_PLACEHOLDER = "__SIP_ID__"
LINK_STATUS_AR = {
    "expired": "الرابط ده انتهت صلاحيته. اطلب من صاحبه يعمل رابط جديد.",
    "revoked": "الرابط ده اتلغى من صاحبه.",
    "invalid": "الرابط ده مش صحيح أو مش موجود.",
    "session": "جلسة Easy eSIM الخاصة بصاحب الرابط انتهت. صاحب الرابط لازم يسجّل دخول تاني على الموقع ويعمل رابط جديد.",
}
OWNER_ONLY_MSG = "الخاصية دي مش متاحة من رابط المشاركة."


def _owner_id(user=None):
    u = user if user is not None else (session.get("user") or {})
    return u.get("google_id") or u.get("email") or ""


def _ctx():
    """Who is calling: the logged-in owner (Google session) or a share-link
    visitor (session holds only the link id; the eSIMEasy session is loaded
    from the server-side store and never put in the cookie)."""
    if "ctx" in g:
        return g.ctx
    ctx = None
    if session.get("user"):
        ctx = {"mode": "owner", "user": session["user"],
               "esim": session.get("esimeasy") or {},
               "phone_auth": bool(session.get("phone_authenticated")),
               "device_id": session.get("device_id"), "owner_id": _owner_id()}
    elif session.get("link_id"):
        status, row = share_links.get_link(session["link_id"])
        owner = share_links.get_owner(row["owner_id"]) if status == "active" else None
        if owner and owner["esim"].get("sessionId"):
            label = row["label"] or ""
            ctx = {"mode": "link",
                   "user": {"name": "رابط مشترك" + (f" — {label}" if label else ""),
                            "email": "", "picture": None, "shared": True},
                   "esim": owner["esim"], "phone_auth": owner["phone_auth"],
                   "device_id": owner["device_id"], "owner_id": row["owner_id"],
                   "link_id": row["id"], "expires_at": row["expires_at"]}
        else:
            g.link_status = status if status != "active" else "session"
            session.pop("link_id", None)
    g.ctx = ctx
    return ctx


def _store_esim(ctx, esim):
    """Persist refreshed eSIMEasy data for the current context."""
    if ctx["mode"] == "owner":
        session["esimeasy"] = esim
        share_links.save_owner(ctx["owner_id"], esim, ctx.get("phone_auth"), ctx.get("device_id"))
    else:
        share_links.update_owner_balances(ctx["owner_id"], esim.get("remainCallPoint"),
                                          esim.get("remainPoint"))
    ctx["esim"] = esim


@app.route("/")
def index():
    ctx = _ctx()
    if ctx and ctx["mode"] == "owner":
        return render_template("dashboard.html", user=ctx["user"], esim=ctx["esim"],
                               expiry_choices=share_links.EXPIRY_CHOICES,
                               default_hours=share_links.DEFAULT_HOURS)
    if ctx:
        return redirect(url_for("dialer"))
    if g.get("link_status"):
        return render_template("share_open.html", message=LINK_STATUS_AR[g.link_status]), 410
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
        session.pop("link_id", None)
        if google_id or email:
            session["esimeasy"] = esimeasy_login(google_id, email)
            # keep existing share links on the owner's newest session
            share_links.save_owner(_owner_id(), session["esimeasy"],
                                   session.get("phone_authenticated"), session.get("device_id"))
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
    ctx = _ctx()
    if not ctx:
        return redirect(url_for("index"))
    esim = ctx["esim"]
    if not esim.get("sessionId"):
        return redirect(url_for("index"))
    countries = sorted(
        ({"code": code, "name": name, "rate": rate}
         for code, entries in RATES.items() for name, rate in entries[:1]),
        key=lambda c: c["name"])
    return render_template("dialer.html", user=ctx["user"],
                           balance=esim.get("remainCallPoint", 0),
                           countries=countries,
                           phone_authenticated=ctx["phone_auth"],
                           shared=ctx["mode"] == "link",
                           link_expires_at=ctx.get("expires_at"),
                           recording=share_links.get_setting(ctx["owner_id"], "recording", "0") == "1",
                           telegram_ready=telegram_bot.READY,
                           expiry_choices=share_links.EXPIRY_CHOICES,
                           default_hours=share_links.DEFAULT_HOURS)


@app.route("/api/call/setup", methods=["POST"])
def api_call_setup():
    ctx = _ctx()
    if not ctx:
        return {"error": "not logged in",
                "message": LINK_STATUS_AR.get(g.get("link_status") or "", "")}, 401
    esim = ctx["esim"]
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
    device_id = ctx.get("device_id") or str(uuid.uuid4())
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
        message = message_for(code, msg)
        expired = False
        if ctx["mode"] == "link" and str(code) not in ("-539", "-516", "-517", "-523", "-558"):
            # tell the visitor clearly when the owner's eSIMEasy session is gone
            expired = _session_info(session_id) is None
            if expired:
                message = LINK_STATUS_AR["session"]
        return {"error": "call setup rejected",
                "retCode": code,
                "retMsg": msg,
                "message": message,
                "sessionExpired": expired,
                "coins": esim.get("remainCallPoint"),
                "points": esim.get("remainPoint")}, 502

    # Log only non-secret diagnostics (never sessionId / webrtcPwd / turnPwd).
    print(f"[call/req] retCode={data.get('retCode')} via={used} callSequence={data.get('callSequence')} "
          f"country_code={country_code} uniqueId={unique_id} networkTp={network_tp} "
          f"isTls={data.get('isTls')} isDtls={data.get('isDtls')} isTurn={data.get('isTurn')} "
          f"fields={sorted(data.keys())}" + (" mode=link" if ctx["mode"] == "link" else ""), flush=True)
    if ctx["mode"] == "link":
        share_links.touch(ctx["link_id"])

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
        "sipIdentity": session_id if ctx["mode"] == "owner" else SIP_ID_PLACEHOLDER,
        # كل الحقول الراجعة من السيرفر من غير فلترة — عشان نشوف أي حاجة ناقصة
        # في الريسبونس من غير ما نفتح Railway logs كل مرة.
        "rawFields": list(data.keys()),
        "coins": esim.get("remainCallPoint"),
        "points": esim.get("remainPoint"),
    }


@app.route("/api/prefix/<code>")
def api_prefix(code):
    if not _ctx():
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
        # Save verified caller number for Telegram logs
        pending = session.get("phone_auth_pending") or {}
        if pending.get("nationalId") and pending.get("phoneId"):
            session["verified_number"] = f"+{pending['nationalId']}{pending['phoneId']}"
        session.pop("phone_auth_pending", None)
        share_links.save_owner(_owner_id(), session.get("esimeasy") or {}, True,
                               session.get("device_id"))
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
        share_links.save_owner(_owner_id(user), result, session.get("phone_authenticated"),
                               session.get("device_id"))
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
    ctx = _ctx()
    if not ctx:
        return {"error": LINK_STATUS_AR.get(g.get("link_status") or "", "not logged in")}, 401
    esim = dict(ctx["esim"])
    info = _session_info(esim["sessionId"]) if esim.get("sessionId") else None
    if info is not None:
        esim["remainCallPoint"] = _num(info.get("remainCallPoint"))
        esim["remainPoint"] = _num(info.get("remainPoint"))
        _store_esim(ctx, esim)
        source = "session"
    elif ctx["mode"] == "link":
        # no re-login from a share link: the owner must log in again
        return {"error": LINK_STATUS_AR["session"], "sessionExpired": True}, 502
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
    if session.get("user") and request.args.get("revoke") == "1":
        n = share_links.revoke_all(_owner_id())
        print(f"[share-links] revoked {n} on logout", flush=True)
    was_link = bool(session.get("link_id")) and not session.get("user")
    for key in ("user", "esimeasy", "phone_authenticated", "phone_auth_pending", "balance",
                "link_id"):
        session.pop(key, None)
    if was_link:
        return render_template("share_open.html", message="خرجت من الرابط المشترك. تقدر تفتحه تاني من نفس الرابط لو لسه صالح.")
    return redirect(url_for("index"))


# ---------- share links ----------
def _owner_ctx():
    ctx = _ctx()
    return ctx if ctx and ctx["mode"] == "owner" else None


def _link_json(r):
    return {"id": r["id"], "label": r.get("label") or "", "created_at": r["created_at"],
            "expires_at": r["expires_at"], "last_used_at": r.get("last_used_at")}


@app.route("/api/links", methods=["GET"])
def api_links_list():
    ctx = _owner_ctx()
    if not ctx:
        return {"error": OWNER_ONLY_MSG}, 403
    return {"links": [_link_json(r) for r in share_links.list_active(ctx["owner_id"])]}


@app.route("/api/links", methods=["POST"])
def api_links_create():
    ctx = _owner_ctx()
    if not ctx:
        return {"error": OWNER_ONLY_MSG}, 403
    if not ctx["esim"].get("sessionId"):
        return {"error": "Easy eSIM مش متصل. اعمل تسجيل دخول الأول."}, 400
    body = request.get_json(force=True, silent=True) or {}
    try:
        hours = int(body.get("hours") or share_links.DEFAULT_HOURS)
    except (TypeError, ValueError):
        hours = share_links.DEFAULT_HOURS
    if hours not in share_links.EXPIRY_CHOICES:
        return {"error": "مدة غير مسموحة"}, 400
    label = str(body.get("label") or "").strip()[:40]
    share_links.save_owner(ctx["owner_id"], ctx["esim"], ctx["phone_auth"], ctx["device_id"],
                           create=True)
    try:
        token, link = share_links.create_link(ctx["owner_id"], hours, label)
    except ValueError:
        return {"error": f"وصلت للحد الأقصى ({share_links.MAX_ACTIVE_LINKS}) من الروابط الشغالة. الغي رابط الأول."}, 400
    print(f"[share-links] created id={link['id']} hours={hours}", flush=True)
    # token goes in the #fragment: browsers never send it in requests, so it
    # cannot end up in HTTP/proxy logs or Referer headers
    url = url_for("share_open", _external=True) + "#" + token
    return {"url": url, "link": _link_json(link)}


@app.route("/api/links/<link_id>/revoke", methods=["POST"])
def api_links_revoke(link_id):
    ctx = _owner_ctx()
    if not ctx:
        return {"error": OWNER_ONLY_MSG}, 403
    ok = share_links.revoke(ctx["owner_id"], link_id)
    if ok:
        print(f"[share-links] revoked id={link_id}", flush=True)
    return ({"ok": True}, 200) if ok else ({"error": "الرابط مش موجود"}, 404)


@app.route("/api/links/revoke-all", methods=["POST"])
def api_links_revoke_all():
    ctx = _owner_ctx()
    if not ctx:
        return {"error": OWNER_ONLY_MSG}, 403
    return {"ok": True, "revoked": share_links.revoke_all(ctx["owner_id"])}


@app.route("/s")
def share_open():
    resp = app.make_response(render_template("share_open.html", message=None))
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/api/links/open", methods=["POST"])
def api_links_open():
    body = request.get_json(force=True, silent=True) or {}
    status, row = share_links.resolve_token(str(body.get("token") or ""))
    if status != "active":
        return {"ok": False, "message": LINK_STATUS_AR[status]}, 410
    owner = share_links.get_owner(row["owner_id"])
    info = _session_info(owner["esim"]["sessionId"]) if owner and owner["esim"].get("sessionId") else None
    if info is None:
        return {"ok": False, "message": LINK_STATUS_AR["session"]}, 410
    share_links.update_owner_balances(row["owner_id"], _num(info.get("remainCallPoint")),
                                      _num(info.get("remainPoint")))
    for key in ("user", "esimeasy", "phone_authenticated", "phone_auth_pending", "balance"):
        session.pop(key, None)
    session.permanent = True
    session["link_id"] = row["id"]
    share_links.touch(row["id"])
    print(f"[share-links] opened id={row['id']}", flush=True)
    return {"ok": True, "redirect": url_for("dialer")}


# ---------- Telegram control channel + call recording ----------
import json as _json

_CONTROL_CLIENTS = {}  # call_id -> ws


@sock.route("/ws-control")
def ws_control(ws):
    """Browser <-> Telegram bridge for one call. Messages are JSON.
    Client: {type:hello, callId, number, country, label, rate, coins}
            {type:connected} | {type:ended, duration, cost}
            {type:ack, action, ok, state?, error?}
            {type:ping}
    Server: {type:cmd, action:end|hold|mute}
    """
    call_id = None
    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break
            if raw == BROWSER_KEEPALIVE:
                continue
            try:
                msg = _json.loads(raw) if isinstance(raw, str) else None
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            t = msg.get("type")
            if t == "hello":
                call_id = str(msg.get("callId") or "")[:40]
                if not call_id:
                    continue
                _CONTROL_CLIENTS[call_id] = ws
                ctx = _ctx() or {}
                label = msg.get("label") or (
                    "رابط مشترك" if ctx.get("mode") == "link" else "الحساب")
                if ctx.get("mode") == "link" and ctx.get("link_id"):
                    label = f"رابط {ctx['link_id'][:8]}"
                caller_num = (ctx.get("verified_number") or
                              session.get("verified_number") or "")
                telegram_bot.register_call(
                    call_id, msg.get("number"), msg.get("country"), label,
                    msg.get("rate"), msg.get("coins"), caller_num)
            elif t == "connected" and call_id:
                telegram_bot.mark_connected(call_id)
            elif t == "ended" and call_id:
                telegram_bot.mark_ended(call_id, msg.get("duration"), msg.get("cost"))
            elif t == "ack" and call_id:
                telegram_bot.ack_cmd(call_id, msg.get("action"), bool(msg.get("ok")),
                                    msg.get("state"), msg.get("error"))
            elif t == "ping":
                try:
                    ws.send(_json.dumps({"type": "pong"}))
                except Exception:
                    pass
            # Pull any pending Telegram command for this call (non-blocking poll loop)
            if call_id:
                # Drain with a short timeout so the receive loop stays responsive;
                # the browser also pings, which re-enters here.
                action = telegram_bot.next_cmd(call_id, timeout=0.01)
                while action:
                    try:
                        ws.send(_json.dumps({"type": "cmd", "action": action}))
                    except Exception:
                        break
                    action = telegram_bot.next_cmd(call_id, timeout=0.01)
    finally:
        if call_id:
            _CONTROL_CLIENTS.pop(call_id, None)
            # If the browser closed without an ended event, notify Telegram.
            if call_id in telegram_bot.active_calls():
                telegram_bot.mark_ended(call_id)


# Background pusher: when Telegram queues a command, push it to the right socket
# without waiting for the next browser message.
def _control_pusher():
    while True:
        gevent.sleep(0.3)
        for cid, ws in list(_CONTROL_CLIENTS.items()):
            action = telegram_bot.next_cmd(cid, timeout=0.01)
            while action:
                try:
                    ws.send(_json.dumps({"type": "cmd", "action": action}))
                except Exception:
                    break
                action = telegram_bot.next_cmd(cid, timeout=0.01)

gevent.spawn(_control_pusher)


@app.route("/api/recording/toggle", methods=["POST"])
def api_recording_toggle():
    ctx = _ctx()
    if not ctx or ctx["mode"] != "owner":
        return {"error": "owner only"}, 403
    body = request.get_json(force=True, silent=True) or {}
    on = bool(body.get("on"))
    share_links.set_setting(ctx["owner_id"], "recording", "1" if on else "0")
    return {"on": on}


@app.route("/api/recording/status")
def api_recording_status():
    ctx = _ctx()
    if not ctx:
        return {"on": False}
    oid = ctx["owner_id"]
    on = share_links.get_setting(oid, "recording", "0") == "1"
    return {"on": on, "tg": telegram_bot.READY}


@app.route("/api/recording/upload", methods=["POST"])
def api_recording_upload():
    """Accept a recorded call audio, send it to Telegram, then delete it."""
    ctx = _ctx()
    if not ctx:
        return {"error": "not logged in"}, 401
    f = request.files.get("audio")
    if not f:
        return {"error": "no audio"}, 400
    duration = request.form.get("duration") or ""
    number = request.form.get("number") or ""
    country = request.form.get("country") or ""
    os.makedirs("/tmp/recordings", exist_ok=True)
    path = f"/tmp/recordings/{uuid.uuid4().hex}.webm"
    try:
        f.save(path)
        caption = ("\U0001F399\ufe0f \u062a\u0633\u062c\u064a\u0644 \u0645\u0643\u0627\u0644\u0645\u0629\n+%s %s\n\u0627\u0644\u0645\u062f\u0629: %s" % (country, telegram_bot.mask_number(number), duration))
        result = telegram_bot.send_audio(path, caption)
        ok = bool(result and result.get("ok"))
        return {"ok": ok}
    except Exception as e:
        print(f"[recording] upload {type(e).__name__}", flush=True)
        return {"error": "upload failed"}, 502
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


@app.route("/health")
def health():
    return {"status": "ok", "telegram": telegram_bot.ENABLED,
            "telegramOwner": telegram_bot.OWNER_ID is not None}


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
