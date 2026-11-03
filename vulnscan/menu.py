import json, glob, os
from datetime import datetime
from .scope import Scope, ScopeError
from .profiles import load_profile
from .recon import port_scan
from .nuclei_mod import nuclei_scan
from .ssl_mod import ssl_check
from .web_mod import web_checks
from .subs_mod import find_subdomains
from . import audit, ownership, guard

SCHEMES = {443: "https", 8443: "https", 80: "http", 8080: "http", 8000: "http"}

def choose(title, items):
    print(f"\n{title}")
    for i, x in enumerate(items, 1):
        print(f"  {i}) {x}")
    return items[int(input("Seçim: ")) - 1]

def main():
    files = sorted(glob.glob("scopes/*.json"))
    if not files:
        print("scopes/ içinde müşteri dosyası yok."); return
    path = choose("Müşteri dosyası:", files)
    data = json.load(open(path))
    cl = data.get("client", "?")
    if not data.get("authorized"):
        audit.log("scan_refused", client=cl, reason="yetki formu onaysız")
        print("Yetki formu onaylı değil (authorized). Durduruldu."); return
    try:
        scope = Scope(path)
        name, prof = load_profile(data)
    except (ScopeError, PermissionError, ValueError) as e:
        audit.log("scan_refused", client=cl, reason=str(e))
        print("Durduruldu:", e); return
    ok, method = ownership.is_verified(data)
    if not ok:
        audit.log("scan_refused", client=cl, reason="sahiplik doğrulanmamış")
        print("Sahiplik doğrulanmamış. Ana menüden '4) Sahiplik doğrula' çalıştır."); return
    host = choose("Hedef:", [t for t in data["targets"] if "*" not in t])
    print(f"\nMüşteri: {cl} | Paket: {name} | Hedef: {host}")
    if input("Başlansın mı? (e/h): ").lower() != "e":
        return
    res = {"client": cl, "host": host, "profile": name, "ownership": method,
           "date": datetime.now().isoformat(timespec="minutes"),
           "ports": [], "findings": [], "ssl": None, "web": None,
           "subdomains": None, "notes": []}

    def step(m, **kw):
        audit.log("module_done", client=cl, host=host, module=m, **kw)

    audit.log("scan_start", client=cl, host=host, profile=name, ownership=method, modules=prof["modules"])
    try:
        if "ports" in prof["modules"]:
            print("Port taraması..."); res["ports"] = port_scan(scope, host)
            step("ports", count=len(res["ports"]))
        urls = [f"{SCHEMES[p['port']]}://{host}:{p['port']}" for p in res["ports"] if p["port"] in SCHEMES]
        if "ssl" in prof["modules"]:
            print("SSL ve başlık kontrolü..."); res["ssl"] = ssl_check(scope, host)
            step("ssl", errors=len(res["ssl"]["errors"]))
        if "web" in prof["modules"]:
            print("Ek başlık, cookie ve yönlendirme kontrolü...")
            res["web"] = web_checks(scope, host)
            step("web", headers=len(res["web"]["headers_missing"]),
                 cookies=len(res["web"]["cookies"]),
                 redirect=(res["web"]["http_redirect"] or {}).get("status"))
        if "subdomains" in prof["modules"]:
            print("Alt alan adı keşfi...")
            try:
                res["subdomains"] = find_subdomains(scope, host)
                ins = [s for s in res["subdomains"]["in_scope"] if s != host][:20]
                urls += [f"https://{s}" for s in ins]
                if res["subdomains"]["out_of_scope"]:
                    res["notes"].append("Kapsam dışı alt alan adları bulundu, taranmadı.")
                step("subdomains", in_scope=len(res["subdomains"]["in_scope"]),
                     out_of_scope=len(res["subdomains"]["out_of_scope"]))
            except RuntimeError as e:
                res["notes"].append(str(e)); print(e)
        if any(m.startswith("nuclei") for m in prof["modules"]):
            if urls:
                urls, gnotes = guard.check_urls(scope, urls)
                res["notes"] += gnotes
                step("guard", kept=len(urls), notes=gnotes)
            if urls:
                print(f"Zafiyet taraması ({len(urls)} adres)...")
                found = nuclei_scan(scope, host, name, prof["rate"], urls)
                res["findings"], dropped = guard.filter_findings(scope, found)
                if dropped:
                    res["notes"].append(f"{dropped} bulgu kapsam dışı adreste olduğu için elendi.")
                step("nuclei", urls=urls, findings=len(res["findings"]), dropped=dropped)
            else:
                res["notes"].append("Taranabilir web adresi bulunamadı, zafiyet taraması yapılmadı.")
                print("Taranabilir web adresi bulunamadı, nuclei atlandı.")
    except ScopeError as e:
        audit.log("scope_blocked", client=cl, host=host, error=str(e))
        print("Kapsam ihlali engellendi:", e); return
    except Exception as e:
        audit.log("scan_error", client=cl, host=host, error=str(e))
        raise
    res["not_tested"] = [m for m in prof["modules"] if m == "webapp"]
    os.makedirs("reports", exist_ok=True)
    out = f"reports/{cl.replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M}.json"
    json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
    audit.log("scan_end", client=cl, host=host, report=out,
              ports=len(res["ports"]), findings=len(res["findings"]))
    print(f"\nBitti. {len(res['ports'])} açık port, {len(res['findings'])} bulgu.")
    if res["subdomains"]:
        print(f"Alt alan adı: {len(res['subdomains']['in_scope'])} kapsamda, "
              f"{len(res['subdomains']['out_of_scope'])} kapsam dışı.")
    if res["ssl"]:
        if res["ssl"]["errors"]:
            print("SSL/başlık kontrolü tamamlanamadı:", "; ".join(res["ssl"]["errors"]))
        else:
            print(f"Eksik güvenlik başlığı: {len(res['ssl']['headers_missing'])}")
    if res["web"]:
        w = res["web"]
        print(f"Ek başlık eksiği: {len(w['headers_missing'])}, "
              f"cookie sorunu: {len(w['cookies'])}, "
              f"yönlendirme: {(w['http_redirect'] or {}).get('status')}")
    for n in res["notes"]:
        print("Not:", n)
    print(f"Kayıt: {out}")

if __name__ == "__main__":
    main()
