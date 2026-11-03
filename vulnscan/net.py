import http.client, socket, ssl, json, urllib.request
from urllib.parse import urlencode

def _ip4(host, port):
    return socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]

class _HTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.create_connection((_ip4(self.host, self.port), self.port), self.timeout)

class _HTTPS(http.client.HTTPSConnection):
    verify = True
    def connect(self):
        s = socket.create_connection((_ip4(self.host, self.port), self.port), self.timeout)
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(s, server_hostname=self.host)

def fetch(host, path="/", scheme="https", port=None, timeout=10, verify=True):
    port = port or (443 if scheme == "https" else 80)
    c = (_HTTPS if scheme == "https" else _HTTP)(host, port, timeout=timeout)
    if scheme == "https":
        c.verify = verify
    try:
        c.request("GET", path, headers={"User-Agent": "VulnScan"})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(65536)
    finally:
        c.close()

def doh_txt(name):
    url = "https://cloudflare-dns.com/dns-query?" + urlencode({"name": name, "type": "TXT"})
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.load(r)
    return [a["data"].strip('"') for a in d.get("Answer", []) if a.get("type") == 16]
