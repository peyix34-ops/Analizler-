import ssl, socket, http.client
from datetime import datetime, timezone

HEADERS = {
    "strict-transport-security": "HSTS yok (HTTPS zorunlu kılınmıyor)",
    "content-security-policy": "CSP yok (XSS'e karşı koruma başlığı eksik)",
    "x-frame-options": "X-Frame-Options yok (clickjacking riski)",
    "x-content-type-options": "X-Content-Type-Options yok",
}

def ssl_check(scope, host):
    scope.require(host)
    res = {"cert": None, "headers_missing": [], "errors": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                res["cert"] = {"expires": exp.date().isoformat(),
                               "days_left": (exp - datetime.now(timezone.utc)).days,
                               "tls": t.version()}
    except ssl.SSLCertVerificationError as e:
        res["errors"].append(f"Sertifika doğrulanamadı: {e.verify_message}")
    except Exception as e:
        res["errors"].append(f"HTTPS bağlantı hatası: {e}")
    try:
        c = http.client.HTTPSConnection(host, timeout=10)
        c.request("GET", "/", headers={"User-Agent": "VulnScan"})
        got = {k.lower() for k, _ in c.getresponse().getheaders()}
        res["headers_missing"] = [m for h, m in HEADERS.items() if h not in got]
    except Exception as e:
        res["errors"].append(f"Başlık kontrolü yapılamadı: {e}")
    return res
