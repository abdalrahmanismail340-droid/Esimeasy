# eSIMEasy Web — Google Login (Railway ready)

صفحة دخول بجوجل + لوحة تحكم بعد الدخول. جاهزة للرفع على Railway.

## 1. اعمل Google OAuth credentials

1. افتح [Google Cloud Console](https://console.cloud.google.com/)
2. اعمل مشروع جديد (أي اسم)
3. من القائمة: **APIs & Services → OAuth consent screen**
   - اختار **External** → املا الاسم والإيميل → ضيف الـ scopes: `openid`, `email`, `profile`
4. من القائمة: **APIs & Services → Credentials → Create Credentials → OAuth client ID**
   - النوع: **Web application**
   - في **Authorized redirect URIs** ضيف:
     - `https://YOUR-APP.up.railway.app/callback` (هتعرفه بعد الرفع)
     - `http://localhost:5000/callback` (للتجربة على جهازك)
5. انسخ الـ **Client ID** والـ **Client Secret**

## 2. الرفع على Railway

1. ارفع المشروع على GitHub (أو `railway up` من الـ CLI)
2. في Railway: **New Project → Deploy from GitHub**
3. ضيف الـ Environment Variables:
   - `GOOGLE_CLIENT_ID` = اللي نسخته
   - `GOOGLE_CLIENT_SECRET` = اللي نسخته
   - `SECRET_KEY` = أي نص عشوائي طويل
4. بعد ما يشتغل، خد رابط التطبيق وضيفه في الـ redirect URIs في جوجل (خطوة 1.4)

## 3. التجربة محلياً

```bash
pip install -r requirements.txt
export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... SECRET_KEY=...
python app.py
```

وافتح `http://localhost:5000`

## الملفات

- `app.py` — التطبيق (Flask + Authlib)
- `templates/login.html` — صفحة الدخول
- `templates/dashboard.html` — صفحة بعد الدخول (مكان الـ Dialer بعدين)
- `Procfile` / `railway.json` / `requirements.txt` — إعدادات Railway
