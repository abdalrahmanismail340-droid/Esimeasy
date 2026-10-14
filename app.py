import os
import uuid
import base64
from datetime import timedelta
from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import requests
from rates import RATES

ESIMEASY_LOGIN_URL = "https://esimapi.esimeasy.co.kr:8444/esimeasyasd/v4/user/login"
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
        session["user"] = {
            "name": userinfo.get("name"),
            "email": userinfo.get("email"),
            "picture": userinfo.get("picture"),
            "google_id": google_id,
        }
        # Auto-login to eSIMEasy with the verified Google user ID,
        # same as the official app does (userId + authenType UAT0002).
        if google_id:
            session["esimeasy"] = esimeasy_login(google_id)
    return redirect(url_for("index"))


def esimeasy_login(google_user_id):
    """Log into eSIMEasy's backend using the Google user ID.

    Returns dict with sessionId / remainCallPoint on success, else {}.
    """
    device_id = session.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
        session["device_id"] = device_id
    # The app AES-encrypts the Google user ID before sending (ww.u0).
    enc_id = esim_encrypt_user_id(google_user_id)
    payload = {
        "userId": enc_id,
        "paramUserId": enc_id,
        "authenType": "UAT0002",
        "paramAuthenType": "UAT0002",
        "deviceOs": "AT0001",
        "deviceId": device_id,
        "deviceModel": "Web",
        "deviceOsVersion": "",
        "deviceOsLanguage": "en",
        "pushToken": "",
        "installRootId": "",
        "isTest": False,
        "appVersion": "3.0.0",
        "languageCd": "en",
    }
    try:
        r = requests.post(ESIMEASY_LOGIN_URL, json=payload, timeout=15)
        data = r.json()
    except Exception as e:
        return {"_error": f"connection: {e}"}
    if not isinstance(data, dict):
        return {"_error": "bad response"}
    if not data.get("sessionId"):
        return {"_error": f"[b2] retCode={data.get('retCode')}",
                "_retCode": data.get("retCode"),
                "_raw": str(data)[:200]}
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
