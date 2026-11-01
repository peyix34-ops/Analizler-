import json, ipaddress, fnmatch
from datetime import date

class ScopeError(Exception):
    pass

class Scope:
    def __init__(self, path):
        with open(path) as f:
            d = json.load(f)
        self.client = d["client"]
        self.start = date.fromisoformat(d["valid_from"])
        self.end = date.fromisoformat(d["valid_until"])
        self.targets = [t.lower() for t in d["targets"]]
        if not (self.start <= date.today() <= self.end):
            raise ScopeError("Yetki süresi dışında, tarama yapılamaz.")

    def allowed(self, host):
        host = host.lower().strip()
        for t in self.targets:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(t, strict=False):
                    return True
            except ValueError:
                pass
            if fnmatch.fnmatch(host, t):
                return True
        return False

    def require(self, host):
        if not self.allowed(host):
            raise ScopeError(f"{host} kapsam dışı, işlem durduruldu.")
