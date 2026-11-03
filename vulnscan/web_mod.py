from urllib.parse import urlparse, urljoin
from .net import fetch_full

HEADERS = {
    "referrer-policy": "Referrer-Policy yok (ziyaretçinin geldiği adres başka sitelere gidebilir)",
    "permissions-policy": "Permissions-Policy yok (kamera, konum gibi tarayıcı özellikleri sınırlanmamış)",
}
HEADER_INFO = {
    "Referrer-Policy": "Ziyaretçi bir bağlantıya tıkladığında geldiği sayfanın adresi karşı siteye gönderilir. Adreste kullanıcıya ait bilgi varsa sızabilir.",
    "Permissions-Policy": "Sitenin kamera, mikrofon, konum gibi tarayıcı özelliklerini kullanıp kullanamayacağı sınırlanmamış. Sitedeki zararlı bir kod bunları kötüye kullanmaya çalışabilir.",
}
COOKIE_INFO = {
    "Secure": "Secure yok: cookie şifresiz (HTTP) bağlantıda da gönderilir, yolda okunabilir.",
    "HttpOnly": "HttpOnly yok: sitedeki zararlı bir kod (XSS) cookie'yi okuyabilir. Oturum cookie'siyse hesap ele geçirilebilir.",
    "SameSite": "SameSite yok: başka siteler kullanıcı adına istek yaptırabilir (CSRF). Modern tarayıcılar bunu kısmen kendileri sınırlar, risk düşüktür.",
}
REDIRECT_INFO = {
    "ok": "HTTP adresi otomatik olarak HTTPS'e yönleniyor. Bu iyi.",
    "missing": "Site şifresiz HTTP olarak da açılıyor ve HTTPS'e yönlendirmiyor. Ziyaretçi şifresiz bağlanırsa bilgileri yolda okunabilir.",
    "stays_http": "HTTP adresi yönleniyor ama yine şifresiz bir adrese. HTTPS'e geçilmiyor.",
    "no_https": "Site sadece HTTP sunuyor, HTTPS yok. Yönlendirilecek şifreli adres bulunmuyor.",
    "http_closed": "HTTP (80) portu kapalı, sorun yok.",
    "other": "HTTP adresi yönlendirme yapmadan hata döndürüyor, değerlendirilemedi.",
}

def _hv(hdrs, name):
    return next((v for k, v in hdrs if k.lower() == name), None)

def _get(host, scheme, hops=3):
    path, cookies = "/", []
    for _ in range(hops + 1):
        st, hdrs, _b = fetch_full(host, path, scheme, verify=False)
        cookies += [v for k, v in hdrs if k.lower() == "set-cookie"]
        loc = _hv(hdrs, "location")
        if 300 <= st < 400 and loc:
            u = urlparse(urljoin(f"{scheme}://{host}{path}", loc))
            if u.hostname == host and u.scheme == scheme:
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                continue
        break
    return st, hdrs, cookies

def _cookie_issues(raw_list, https):
    out = []
    for raw in raw_list:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        miss = []
        if https and "secure" not in flags:
            miss.append("Secure")
        if "httponly" not in flags:
            miss.append("HttpOnly")
        if "samesite" not in flags:
            miss.append("SameSite")
        if miss:
            out.append({"name": name, "missing": miss})
    return out

def _redirect_state(st, hdrs, host, https_ok):
    loc = _hv(hdrs, "location")
    if 300 <= st < 400 and loc:
        u = urlparse(urljoin(f"http://{host}/", loc))
        return {"status": "ok" if u.scheme == "https" else "stays_http", "to": loc}
    if st >= 400:
        return {"status": "other", "http_status": st}
    return {"status": "missing" if https_ok else "no_https", "http_status": st}

def web_checks(scope, host):
    scope.require(host)
    res = {"page": None, "headers_missing": [], "cookies": [], "http_redirect": None, "errors": []}
    page, https_ok = None, False
    try:
        page = _get(host, "https")
        https_ok = True
        res["page"] = f"https://{host}/"
    except Exception as e:
        res["errors"].append(f"HTTPS sayfası okunamadı: {e}")
    try:
        st, hdrs, _b = fetch_full(host, "/", "http", verify=False)
        res["http_redirect"] = _redirect_state(st, hdrs, host, https_ok)
        if page is None:
            page = _get(host, "http")
            res["page"] = f"http://{host}/"
    except Exception:
        if res["http_redirect"] is None:
            res["http_redirect"] = {"status": "http_closed"}
        else:
            res["errors"].append("HTTP sayfası okunamadı.")
    if page:
        st, hdrs, cookies = page
        got = {k.lower() for k, _v in hdrs}
        res["headers_missing"] = [m for h, m in HEADERS.items() if h not in got]
        res["cookies"] = _cookie_issues(cookies, https_ok)
    else:
        res["errors"].append("Başlık ve cookie kontrolü yapılamadı: sayfa okunamadı.")
    return res

def explain_web(web, w, title):
    title("EK BAŞLIKLAR, COOKIE VE YÖNLENDİRME")
    if not web:
        print("Bu pakette yapılmadı."); return
    w("Sadece ana sayfa kontrol edildi. Giriş yapınca ya da başka sayfalarda atanan cookie'ler görülmez. Cookie değerleri kaydedilmez, sadece adları ve bayrakları.", "")
    if web["page"]:
        print(f"\nKontrol edilen: {web['page']}")
    for e in web["errors"]:
        w("Uyarı: " + e, "")
    for m in web["headers_missing"]:
        print(f"\n* Eksik: {m}")
        for k, v in HEADER_INFO.items():
            if m.startswith(k):
                w(v)
    if web["page"] and not web["headers_missing"]:
        print("\nReferrer-Policy ve Permissions-Policy mevcut.")
    for c in web["cookies"]:
        print(f"\n* Cookie '{c['name']}': eksik bayrak: {', '.join(c['missing'])}")
        for m in c["missing"]:
            w(COOKIE_INFO[m])
    if web["page"] and not web["cookies"]:
        print("\nCookie sorunu görülmedi (ya da ana sayfa cookie atamıyor).")
    r = web.get("http_redirect") or {}
    print("\nHTTP -> HTTPS yönlendirmesi:")
    w(REDIRECT_INFO.get(r.get("status"), "Değerlendirilemedi."), "")
