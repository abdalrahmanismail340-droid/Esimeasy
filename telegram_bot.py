"""Telegram bot: call notifications and remote control for the panel.

- Enabled only when TELEGRAM_BOT_TOKEN is set; otherwise every function is a no-op.
- Only TELEGRAM_OWNER_ID (numeric user id) is served. Everyone else is ignored.
  Without TELEGRAM_OWNER_ID the bot only answers /start with the sender's id.
- Long polling in a gevent greenlet (single gevent worker). Railway stops the
  previous container before the new one, so there is never a second poller.
- The token is never logged. Errors are logged by type only, so the URL (which
  contains the token) never reaches the logs.
"""
import json
import math
import os
import time

import gevent
from gevent.queue import Queue
from gevent.lock import Semaphore
import requests

TOKEN = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
OWNER_RAW = (os.environ.get("TELEGRAM_OWNER_ID") or "").strip()
OWNER_ID = int(OWNER_RAW) if OWNER_RAW.lstrip("-").isdigit() else None

# ---------- admin list (persistent) ----------
_ADMINS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tg_admins.json")

def _load_admins():
    try:
        with open(_ADMINS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return set(int(x) for x in data if str(x).lstrip("-").isdigit())
    except Exception:
        return set()

def _save_admins(admins):
    try:
        with open(_ADMINS_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(admins), f)
    except Exception as e:
        print(f"[tg] save admins failed: {type(e).__name__}", flush=True)

def is_admin(uid):
    try:
        uid = int(uid)
    except Exception:
        return False
    if OWNER_ID is not None and uid == OWNER_ID:
        return True
    return uid in _load_admins()

def is_owner(uid):
    try:
        return OWNER_ID is not None and int(uid) == OWNER_ID
    except Exception:
        return False
API_BASE = (os.environ.get("TELEGRAM_API_BASE") or "https://api.telegram.org").rstrip("/")
ENABLED = bool(TOKEN)
READY = ENABLED and OWNER_ID is not None

# call_id -> {number, country, label, started, connected_at, muted, held, coins_before, rate}
_calls = {}
_cmds = {}        # call_id -> Queue of commands for the browser
_pending = {}     # call_id -> waiters for hold/mute ACKs
_lock = Semaphore()


def _api(method, **kw):
    if not ENABLED:
        return None
    try:
        r = requests.post(f"{API_BASE}/bot{TOKEN}/{method}", timeout=kw.pop("timeout", 30), **kw)
        return r.json()
    except Exception as e:
        print(f"[tg] {method} {type(e).__name__}", flush=True)
        return None


def send(text, reply_markup=None, chat_id=None):
    if not READY and chat_id is None:
        return
    payload = {"chat_id": chat_id or OWNER_ID, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    if reply_markup is not None:
        payload["reply_markup"] = json.dumps(reply_markup)
    return _api("sendMessage", json=payload)


def send_audio(path, caption=""):
    if not READY:
        return
    try:
        with open(path, "rb") as f:
            return _api("sendAudio", data={"chat_id": OWNER_ID, "caption": caption},
                        files={"audio": ("call.webm", f, "audio/webm")}, timeout=120)
    except Exception as e:
        print(f"[tg] sendAudio {type(e).__name__}", flush=True)
        return None


def mask_number(n):
    d = "".join(c for c in str(n or "") if c.isdigit())
    if len(d) <= 4:
        return "****"
    return d[:2] + "*" * (len(d) - 4) + d[-2:]


def _kb(call_id, muted=False, held=False):
    return {"inline_keyboard": [[
        {"text": "📵 إنهاء", "callback_data": f"end:{call_id}"},
        {"text": ("▶️ استئناف" if held else "⏸️ تعليق"), "callback_data": f"hold:{call_id}"},
        {"text": ("🎙️ فتح الميك" if muted else "🔇 كتم"), "callback_data": f"mute:{call_id}"},
    ]]}


# ---------- call lifecycle (called from the control WebSocket) ----------
def register_call(call_id, number, country, label, rate, coins, caller=""):
    if not READY:
        return
    full_number = f"+{country} {number}"
    with _lock:
        _calls[call_id] = {
            "number": number, "country": country or "?", "label": label or "الحساب",
            "caller": caller,
            "started": time.time(), "connected_at": None, "muted": False, "held": False,
            "coins_before": coins, "rate": rate or 0,
        }
        _cmds[call_id] = Queue()
    caller_txt = f"\nالمتصل: <code>{caller}</code>" if caller else ""
    send(f"📞 <b>مكالمة جديدة</b>\n"
         f"الرقم: <code>{full_number}</code>{caller_txt}\n"
         f"المصدر: {label or 'الحساب'}\n"
         f"الحالة: جاري الرن...",
         reply_markup=_kb(call_id))


def mark_connected(call_id):
    with _lock:
        c = _calls.get(call_id)
        if not c:
            return
        c["connected_at"] = time.time()
        muted, held = c["muted"], c["held"]
        number, country, label = c["number"], c["country"], c["label"]
    caller = c.get("caller", "")
    caller_txt = f"\nالمتصل: <code>{caller}</code>" if caller else ""
    send(f"✅ <b>اتصلت</b>\n"
         f"<code>+{country} {number}</code> • {label}{caller_txt}",
         reply_markup=_kb(call_id, muted, held))


def mark_ended(call_id, duration_sec=None, cost=None):
    with _lock:
        c = _calls.pop(call_id, None)
        _cmds.pop(call_id, None)
        waiters = _pending.pop(call_id, None) or {}
        for q in waiters.values():
            try:
                q.put({"ok": False, "error": "ended"})
            except Exception:
                pass
    if not c:
        return
    if duration_sec is None:
        t0 = c["connected_at"] or c["started"]
        duration_sec = max(0, int(time.time() - t0))
    if cost is None and c["rate"] and c["connected_at"]:
        cost = math.ceil(max(1, duration_sec) / 60) * c["rate"]
    mm, ss = divmod(int(duration_sec or 0), 60)
    cost_txt = f"\nالتكلفة التقريبية: ~{int(cost)} C" if cost else ""
    caller = c.get("caller", "")
    caller_txt = f"\nالمتصل: <code>{caller}</code>" if caller else ""
    send(f"📴 <b>انتهت المكالمة</b>\n"
         f"<code>+{c['country']} {c['number']}</code> • {c['label']}{caller_txt}\n"
         f"المدة: {mm:02d}:{ss:02d}{cost_txt}")


def queue_cmd(call_id, action):
    """Put a command for the browser. Returns a Queue that receives the ACK."""
    with _lock:
        q = _cmds.get(call_id)
        if not q:
            return None
        ack = Queue(maxsize=1)
        _pending.setdefault(call_id, {})[action] = ack
        q.put(action)
        return ack


def next_cmd(call_id, timeout=25):
    q = _cmds.get(call_id)
    if not q:
        return None
    try:
        return q.get(timeout=timeout)
    except Exception:
        return None


def ack_cmd(call_id, action, ok, state=None, error=None):
    with _lock:
        waiters = _pending.get(call_id) or {}
        ack = waiters.pop(action, None)
        c = _calls.get(call_id)
        if c and state:
            if "muted" in state:
                c["muted"] = bool(state["muted"])
            if "held" in state:
                c["held"] = bool(state["held"])
    if ack:
        try:
            ack.put({"ok": ok, "state": state, "error": error})
        except Exception:
            pass


def active_calls():
    with _lock:
        return dict(_calls)


# ---------- command handlers ----------
def _help():
    return ("أوامر البوت:\n"
            "/calls — المكالمات الشغالة\n"
            "/balance — رصيد الكوينز\n"
            "/links — روابط المشاركة\n"
            "/newlink 1h|24h|7d — إنشاء رابط\n"
            "/revoke &lt;id&gt; — إلغاء رابط\n"
            "/help — المساعدة\n\n"
            "كل مكالمة جديدة بتيجي بإشعار وأزرار إنهاء / تعليق / كتم.")


def _handle_start(chat_id, from_id):
    if OWNER_ID is None:
        send(f"أهلاً. رقمك في تيليجرام: <code>{from_id}</code>\n\n"
             f"حط الرقم ده في متغير Railway اسمه <code>TELEGRAM_OWNER_ID</code> "
             f"جنب <code>TELEGRAM_BOT_TOKEN</code>، وبعدين اعمل Redeploy.",
             chat_id=chat_id)
        return
    if not is_admin(from_id):
        return  # ignore strangers
    send(f"أهلاً 👋\n{_help()}")


def _handle_text(text, from_id=None):
    import share_links as S
    parts = text.strip().split()
    cmd = (parts[0].split("@")[0] if parts else "").lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("/help", "/start"):
        send(_help()); return

    if cmd == "/balance":
        oid = S.latest_owner()
        owner = S.get_owner(oid) if oid else None
        if not owner or not owner["esim"].get("sessionId"):
            send("مفيش جلسة Easy eSIM محفوظة. سجّل دخول على الموقع الأول."); return
        coins = owner["esim"].get("remainCallPoint", "?")
        send(f"💰 رصيد الكوينز: <b>{coins} C</b>"); return

    if cmd == "/addadmin":
        if not is_owner(from_id):
            send("الأمر ده للأونر بس."); return
        if not arg.lstrip("-").isdigit():
            send("استخدم: <code>/addadmin 123456789</code>"); return
        admins = _load_admins()
        admins.add(int(arg))
        _save_admins(admins)
        send(f"✅ بقى أدمن: <code>{arg}</code>"); return

    if cmd == "/deladmin":
        if not is_owner(from_id):
            send("الأمر ده للأونر بس."); return
        if not arg.lstrip("-").isdigit():
            send("استخدم: <code>/deladmin 123456789</code>"); return
        admins = _load_admins()
        admins.discard(int(arg))
        _save_admins(admins)
        send(f"🗑️ اتشال من الأدمنز: <code>{arg}</code>"); return

    if cmd == "/admins":
        if not is_owner(from_id):
            send("الأمر ده للأونر بس."); return
        admins = _load_admins()
        if not admins:
            send("مفيش أدمنز مضافين."); return
        send("👥 الأدمنز:\n" + "\n".join(f"• <code>{a}</code>" for a in sorted(admins))); return

    if cmd == "/links":
        oid = S.latest_owner()
        if not oid:
            send("مفيش حساب مربوط."); return
        links = S.list_active(oid)
        if not links:
            send("مفيش روابط شغالة."); return
        lines = ["🔗 الروابط الشغالة:"]
        for l in links:
            rem = max(0, l["expires_at"] - int(time.time()))
            lines.append(f"• <code>{l['id']}</code> {l.get('label') or ''} "
                         f"(باقي {rem // 3600}س) — /revoke_{l['id']}")
        send("\n".join(lines)); return

    if cmd == "/newlink":
        hours_map = {"1h": 1, "24h": 24, "7d": 168, "1": 1, "24": 24, "168": 168}
        hours = hours_map.get(arg.lower() or "24h")
        if hours is None:
            send("استخدم: /newlink 1h أو 24h أو 7d"); return
        oid = S.latest_owner()
        owner = S.get_owner(oid) if oid else None
        if not owner or not owner["esim"].get("sessionId"):
            send("سجّل دخول على الموقع الأول."); return
        S.save_owner(oid, owner["esim"], owner["phone_auth"], owner["device_id"], create=True)
        try:
            token, link = S.create_link(oid, hours, "tg")
        except ValueError as e:
            send(f"فشل: {e}"); return
        # The panel domain is needed for a usable URL. Prefer PUBLIC_BASE_URL.
        base = (os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RAILWAY_PUBLIC_DOMAIN") or "").rstrip("/")
        if base and not base.startswith("http"):
            base = "https://" + base
        url = f"{base}/s#{token}" if base else f"/s#{token}"
        send(f"✅ رابط جديد ({hours} ساعة)\nid: <code>{link['id']}</code>\n"
             f"<code>{url}</code>\n(الرابط ده بيظهر مرة واحدة — انسخه دلوقتي)"); return

    if cmd.startswith("/revoke"):
        lid = arg or cmd.replace("/revoke_", "").replace("/revoke", "")
        oid = S.latest_owner()
        if not oid or not lid:
            send("استخدم: /revoke <id>"); return
        ok = S.revoke(oid, lid)
        send("✅ اتلغى" if ok else "الرابط مش موجود"); return

    if cmd == "/calls":
        calls = active_calls()
        if not calls:
            send("مفيش مكالمات شغالة دلوقتي."); return
        now = time.time()
        for cid, c in calls.items():
            t0 = c["connected_at"] or c["started"]
            mm, ss = divmod(int(now - t0), 60)
            state = "متعلق" if c["held"] else ("مكتوم" if c["muted"] else ("متصل" if c["connected_at"] else "بيرن"))
            send(f"📞 <code>+{c['country']} {c['number']}</code>\n"
                 f"{c['label']} • {state} • {mm:02d}:{ss:02d}",
                 reply_markup=_kb(cid, c["muted"], c["held"]))
        return

    send("أمر مش معروف. /help")


def _handle_callback(cb):
    data = cb.get("data") or ""
    cb_id = cb.get("id")
    from_id = (cb.get("from") or {}).get("id")
    if not is_admin(from_id):
        return
    try:
        action, call_id = data.split(":", 1)
    except ValueError:
        return
    if action not in ("end", "hold", "mute"):
        return
    if call_id not in _calls:
        _api("answerCallbackQuery", json={"callback_query_id": cb_id, "text": "المكالمة خلصت", "show_alert": True})
        return
    _api("answerCallbackQuery", json={"callback_query_id": cb_id, "text": "جاري..."})
    ack = queue_cmd(call_id, action)
    if ack is None:
        send("المتصفح مش متصل دلوقتي."); return
    try:
        result = ack.get(timeout=12)
    except Exception:
        result = {"ok": False, "error": "timeout"}
    if not result.get("ok"):
        send(f"⚠️ فشل {action}: {result.get('error') or 'المتصفح مردّش'}"); return
    state = result.get("state") or {}
    with _lock:
        c = _calls.get(call_id)
        if c:
            muted, held = c["muted"], c["held"]
            number, country, label = c["number"], c["country"], c["label"]
        else:
            return
    verb = {"end": "📵 طلب إنهاء", "hold": ("⏸️ متعلق" if held else "▶️ استؤنفت"),
            "mute": ("🔇 مكتومة" if muted else "🎙️ الميك مفتوح")}[action]
    if action != "end":
        send(f"{verb}\n<code>+{country} {mask_number(number)}</code>",
             reply_markup=_kb(call_id, muted, held))


def _process_update(u):
    if "message" in u:
        msg = u["message"]
        chat_id = (msg.get("chat") or {}).get("id")
        from_id = (msg.get("from") or {}).get("id")
        text = msg.get("text") or ""
        if not text:
            return
        if text.startswith("/start") or OWNER_ID is None:
            _handle_start(chat_id, from_id); return
        if not is_admin(from_id):
            return
        _handle_text(text, from_id)
    elif "callback_query" in u:
        _handle_callback(u["callback_query"])


def _poll_loop():
    offset = 0
    # Drop any webhook so getUpdates works (in case one was set earlier).
    _api("deleteWebhook", json={"drop_pending_updates": False}, timeout=10)
    print("[tg] poller started", flush=True)
    while True:
        try:
            data = _api("getUpdates", json={"offset": offset, "timeout": 25,
                                            "allowed_updates": ["message", "callback_query"]},
                        timeout=35)
            if not data or not data.get("ok"):
                gevent.sleep(2); continue
            for u in data.get("result") or []:
                offset = max(offset, int(u.get("update_id", 0)) + 1)
                try:
                    _process_update(u)
                except Exception as e:
                    print(f"[tg] update {type(e).__name__}", flush=True)
        except Exception as e:
            print(f"[tg] poll {type(e).__name__}", flush=True)
            gevent.sleep(3)


def start():
    if not ENABLED:
        print("[tg] disabled (no TELEGRAM_BOT_TOKEN)", flush=True)
        return
    if OWNER_ID is None:
        print("[tg] token set but TELEGRAM_OWNER_ID missing — /start only", flush=True)
    gevent.spawn(_poll_loop)
