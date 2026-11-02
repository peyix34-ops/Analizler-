import ssl, socket
from datetime import datetime, timezone

HEADERS = {
    "strict-transport-security": "HSTS yok (HTTPS zorunlu kılınmıyor)",
    "content-security-policy": "CSP yok (XSS'e karşı koruma başlığı eksik)",
    "x-frame-options": "X-Frame-Options yok (clickjacking riski)",
    "x-content-type-options": "X-Content-Type-Options yok",
}

def ssl_check(scope, host):
    scope.require(host)
    res = {"https_available": False, "cert": None, "headers_missing": [], "errors": []}
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        with socket.create_connection((ip, 443), timeout=10) as s:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(s, server_hostname=host) as t:
                res["https_available"] = True
                cert = t.getpeercert()
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                res["cert"] = {"expires": exp.date().isoformat(),
                               "days_left": (exp - datetime.now(timezone.utc)).days,
                               "tls": t.version()}
                t.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VulnScan\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = t.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                lines = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")[1:]
                got = {l.split(":", 1)[0].strip().lower() for l in lines if ":" in l}
                res["headers_missing"] = [m for h, m in HEADERS.items() if h not in got]
    except ssl.SSLCertVerificationError as e:
        res["https_available"] = True
        res["errors"].append(f"Sertifika doğrulanamadı: {e.verify_message}")
    except OSError as e:
        res["errors"].append(f"HTTPS (443) kapalı ya da erişilemiyor: {e}")
    return res
