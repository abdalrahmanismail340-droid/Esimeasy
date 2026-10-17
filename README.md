# eSIMEasy Web — Dialer (Railway ready)

تطبيق Flask: دخول بجوجل ← تسجيل دخول eSIMEasy ← دايلر بيتصل عن طريق SIP over WebSocket + WebRTC.

> ⚠️ ده عميل غير رسمي. استخدامه ممكن يكون ضد شروط eSIMEasy والحساب ممكن يتقفل.

## المتغيرات (Railway Variables)

| المتغير | ملاحظات |
|---|---|
| `GOOGLE_CLIENT_ID` | من Google Cloud Console (OAuth client — Web application) |
| `GOOGLE_CLIENT_SECRET` | نفس المكان |
| `SECRET_KEY` | نص عشوائي طويل (لازم يتحط، وإلا الجلسات مش آمنة) |

في Google Console ضيف الـ redirect URI: `https://YOUR-APP.up.railway.app/callback` (و`http://localhost:5000/callback` للتجربة).

## التشغيل على Railway

- الـ builder: **Railpack**، وPython متثبت على **3.12** (`.python-version`).
- أمر التشغيل (في `railway.json` و`Procfile`، ولازم يكون نفسه في إعدادات الخدمة لو متغير هناك):

```
gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1 --timeout 0
```

  - `--worker-class gevent` إجباري: الـ `/ws-proxy` بيفضل مفتوح طول المكالمة. الـ worker العادي (sync) بيتقفل بعد 30 ثانية وبيقطع المكالمة وبيوقف الموقع كله.
  - `--workers 1`: البروكسي والجلسة بيشتغلوا على process واحدة.
  - `--timeout 0`: عشان المكالمات الطويلة متتقطعش.
- Health check: `/health`.

## التشغيل محلياً

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... SECRET_KEY=...
gunicorn app:app --bind 0.0.0.0:5000 --worker-class gevent --workers 1 --timeout 0
```

## الصفحات والـ API

- `/` — الدخول / لوحة التحكم (الرصيد + زرار تحديث، وزرار "حاول تاني" لو دخول eSIMEasy فشل)
- `/dialer` — الدايلر. الأرقام اللي بتبدأ بـ `0` بتتحسب على الدولة المختارة (مصر +20 افتراضي)، والأرقام اللي بتبدأ بـ `+` أو `00` الدولة بتتعرف لوحدها.
- `/rates` — حساب الدقايق حسب الرصيد
- `/ws-monitor` — أداة تشخيص الـ WebSocket
- `POST /api/call/setup` — بيطلب بيانات المكالمة من eSIMEasy (`call/req`)
- `POST /api/phone-auth/req` و`/res` — توثيق رقمك بكود واتساب (إجباري قبل المكالمات)
- `POST /api/esim/refresh` — بيعمل دخول تاني لـ eSIMEasy ويرجع الرصيد الجديد
- `POST /esim/retry` — إعادة محاولة دخول eSIMEasy
- `/ws-proxy` — بروكسي WebSocket بين المتصفح وسيرفر الـ SIP (بيبلع رسايل الـ keepalive `__ka__` من المتصفح، وبيبعت WebSocket ping للسيرفر كل 15 ثانية)

## الملفات

- `app.py` — السيرفر (Flask + Authlib + flask-sock)
- `templates/dialer.html` — الدايلر وكل منطق SIP/WebRTC
- `rates.py` — أسعار الدقيقة لكل كود
- `iso3_codes.py` — كود الاتصال ← ISO3 (من الـ APK) + `RATE_PREFIX_ALIASES` (ألاسكا/هاواي/بورتوريكو بتتطلب على كود 1)
