from urllib.parse import urlparse, urljoin
from .net import fetch

def check_urls(scope, urls):
    ok, notes = [], []
    for u in urls:
        p = urlparse(u)
        scope.require(p.hostname)
        try:
            st, h, _ = fetch(p.hostname, p.path or "/", p.scheme, p.port, verify=False)
        except Exception as e:
            notes.append(f"{u} erişilemedi, taranmadı ({e})")
            continue
        loc = h.get("location")
        if 300 <= st < 400 and loc:
            t = urlparse(urljoin(u, loc)).hostname
            if t and not scope.allowed(t):
                notes.append(f"{u} kapsam dışı adrese yönleniyor ({t}), taranmadı.")
                continue
        ok.append(u)
    return ok, notes

def filter_findings(scope, findings):
    keep, dropped = [], 0
    for f in findings:
        h = urlparse(f.get("url") or "").hostname
        if h and not scope.allowed(h):
            dropped += 1
        else:
            keep.append(f)
    return keep, dropped
