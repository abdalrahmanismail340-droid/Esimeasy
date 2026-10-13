import os
from flask import Flask, redirect, url_for, session, render_template
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

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
        return render_template("dashboard.html", user=user)
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
        session["user"] = {
            "name": userinfo.get("name"),
            "email": userinfo.get("email"),
            "picture": userinfo.get("picture"),
        }
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
