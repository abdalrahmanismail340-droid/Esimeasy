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
- `POST /api/esim/refresh` — بيجيب الرصيد من `session/info/v1`: الكوينز (C، للمكالمات) والنقاط (P). لو الجلسة انتهت بيعمل دخول تاني
- `POST /esim/retry` — إعادة محاولة دخول eSIMEasy
- `/ws-proxy` — بروكسي WebSocket بين المتصفح وسيرفر الـ SIP (بيبلع رسايل الـ keepalive `__ka__` من المتصفح، وبيبعت WebSocket ping للسيرفر كل 15 ثانية)

## أكواد الأخطاء

`retcodes.py` فيه معاني أكواد eSIMEasy بالعربي (من نصوص التطبيق الرسمي v1.8.8)، مثلاً `-539` = الكوينز مش كفاية، `-523` = دولة مش مدعومة، `-545` = الحساب موقوف.

## طلب المكالمة

`call/req` بيتبعت بنفس حقول التطبيق الرسمي بالظبط (appVersion `1.8.8` و networkTp حسب نوع الشبكة). لو اترفض لسبب مش متعلق بالحساب/الرقم، بيتجرب مرة واحدة بالشكل القديم (appVersion `3.0.0` + حقول الجهاز) اللي كان شغال.

## روابط المشاركة (من غير تسجيل دخول)

من الصفحة الرئيسية أو الدايلر: اختار المدة (ساعة / 24 ساعة / 7 أيام) واضغط **إنشاء رابط**، وانسخ الرابط (بيظهر مرة واحدة).
اللي يفتح الرابط بيدخل على الدايلر على حسابك وبيتخصم من كوينزك (C)، من غير Google.

- الرابط شكله `https://.../s#<token>`. الـ token عشوائي (`secrets.token_urlsafe(32)`) ومكتوب بعد `#`، فالمتصفح مبيبعتوش في أي request، وبالتالي مبيظهرش في لوجات HTTP ولا في الـ Referer.
- الـ sessionId ورقمك مش موجودين في الرابط. الداتابيز بتحفظ hash للـ token بس، وجلسة Easy eSIM متشفرة (Fernet بمفتاح مشتق من `SECRET_KEY`).
- حتى متصفح اللي فاتح الرابط مبيشوفش الـ sessionId: في رسالة SIP بيتبعت placeholder، والـ `/ws-proxy` هو اللي بيبدله.
- الروابط بتمشي ورا آخر تسجيل دخول ليك، فلو عملت login تاني الروابط بتكمل شغالة.
- لو جلسة Easy eSIM انتهت، اللي فاتح الرابط بتظهرله رسالة عربي إن صاحب الرابط لازم يسجّل دخول تاني ويعمل رابط جديد.
- فيه قايمة بالروابط الشغالة وزرار **إلغاء** لكل رابط، وزرار «تسجيل الخروج + إلغاء كل الروابط».
- التخزين SQLite. على Railway بيتحط على volume (`RAILWAY_VOLUME_MOUNT_PATH`، متركب على `/data`)، فالروابط بتعيش بعد الـ restart والـ redeploy. من غير volume بيتحط في `./data`، وده بيتمسح مع كل deploy. ممكن تحدد المسار بنفسك بـ `LINKS_DB_PATH`.
- لو `SECRET_KEY` اتغير، كل الروابط بتقف.

## الملفات

- `app.py` — السيرفر (Flask + Authlib + flask-sock)
- `templates/dialer.html` — الدايلر وكل منطق SIP/WebRTC
- `rates.py` — أسعار الدقيقة لكل كود
- `share_links.py` — تخزين روابط المشاركة (SQLite)
- `retcodes.py` — أكواد الأخطاء ← رسائل عربي
- `iso3_codes.py` — كود الاتصال ← ISO3 (من الـ APK) + `RATE_PREFIX_ALIASES` (ألاسكا/هاواي/بورتوريكو بتتطلب على كود 1)
