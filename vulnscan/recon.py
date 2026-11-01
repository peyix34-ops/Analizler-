import shutil, subprocess, sys
import xml.etree.ElementTree as ET
from .scope import Scope

def port_scan(scope, host, ports="1-1000"):
    scope.require(host)
    if not shutil.which("nmap"):
        raise RuntimeError("nmap yok: pkg install nmap")
    r = subprocess.run(
        ["nmap", "-sT", "-Pn", "-sV", "--open", "-p", ports, "-oX", "-", host],
        capture_output=True, text=True, timeout=900)
    found = []
    for p in ET.fromstring(r.stdout).iter("port"):
        svc = p.find("service")
        found.append({
            "port": int(p.get("portid")),
            "proto": p.get("protocol"),
            "service": svc.get("name", "?") if svc is not None else "?",
            "version": " ".join(filter(None, [
                svc.get("product"), svc.get("version")])) if svc is not None else "",
        })
    return found

if __name__ == "__main__":
    sc = Scope(sys.argv[1])
    for x in port_scan(sc, sys.argv[2]):
        print(x)
