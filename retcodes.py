"""eSIMEasy API retCodes -> Arabic (Egyptian) messages.

Codes and meanings come from the official Android app v1.8.8
(res/values/strings.xml error_* strings, handled in cs.java).
retCode 1 (and 2 for login) means success.
"""

RETCODE_MESSAGES_AR = {
    -200: "المنتج مش آخر إصدار. اقفل الصفحة وافتحها تاني.",
    -502: "الحساب ده اتمسح. كلم خدمة عملاء eSIMEasy.",
    -515: "محتاج تكلم خدمة عملاء eSIMEasy.",
    -516: "الرقم ده مينفعش يتطلب. راجع الرقم وجرب تاني.",
    -517: "الرقم ده مينفعش يتطلب. راجع الرقم وجرب تاني.",
    -523: "الدولة دي مش مدعومة للمكالمات.",
    -539: "رصيد Easy Coins مش كفاية للمكالمة. اشحن كوينز (C) من شاشة الاتصال (Dial) في التطبيق — النقاط (P) مبتنفعش للمكالمات.",
    -543: "حصل خطأ. جرب تاني.",
    -544: "بقالك أكتر من سنة مستخدمتش الحساب. اعمل تسجيل خروج ودخول تاني.",
    -545: "الحساب ده موقوف. كلم خدمة عملاء eSIMEasy.",
    -557: "الخدمة مش متاحة من بلدك.",
    -558: "الرقم مش صحيح. الخدمة بتدعم أرقام الموبايل بس.",
    -559: "فشل المزامنة مع السيرفر. اعمل تسجيل خروج ودخول تاني.",
    -615: "السيرفر طالب تحديث للتطبيق.",
    -627: "الرقم ده متوثق قبل كده.",
    -900: "السيرفر في صيانة دلوقتي. جرب بعدين.",
}

# Rejections that describe the account / number, not our request format.
# Retrying with a different request shape will not help for these.
DEFINITIVE_CALL_CODES = {-502, -515, -516, -517, -523, -539, -544, -545, -557, -558, -900}


def _as_int(code):
    try:
        return int(str(code).strip())
    except (TypeError, ValueError):
        return None


def message_for(code, fallback=""):
    c = _as_int(code)
    if c in RETCODE_MESSAGES_AR:
        return RETCODE_MESSAGES_AR[c]
    return fallback


def is_definitive(code):
    return _as_int(code) in DEFINITIVE_CALL_CODES
