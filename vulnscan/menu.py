import json, glob, os
from datetime import datetime
from .scope import Scope, ScopeError
from .profiles import load_profile
from .recon import port_scan
from .nuclei_mod import nuclei_scan
from .ssl_mod import ssl_check
from .subs_mod import find_subdomains

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
    if not data.get("authorized"):
        print("Yetki formu onaylı değil (authorized). Durduruldu."); return
    try:
        scope = Scope(path)
        name, prof = load_profile(data)
    except (ScopeError, PermissionError, ValueError) as e:
        print("Durduruldu:", e); return
    host = choose("Hedef:", [t for t in data["targets"] if "*" not in t])
    print(f"\nMüşteri: {data['client']} | Paket: {name} | Hedef: {host}")
    if input("Başlansın mı? (e/h): ").lower() != "e":
        return
    res = {"client": data["client"], "host": host, "profile": name,
           "date": datetime.now().isoformat(timespec="minutes"),
           "ports": [], "findings": [], "ssl": None, "subdomains": None, "notes": []}
    if "ports" in prof["modules"]:
        print("Port taraması..."); res["ports"] = port_scan(scope, host)
    urls = [f"{SCHEMES[p['port']]}://{host}:{p['port']}" for p in res["ports"] if p["port"] in SCHEMES]
    if "ssl" in prof["modules"]:
        print("SSL ve başlık kontrolü..."); res["ssl"] = ssl_check(scope, host)
    if "subdomains" in prof["modules"]:
        print("Alt alan adı keşfi...")
        try:
            res["subdomains"] = find_subdomains(scope, host)
            ins = [s for s in res["subdomains"]["in_scope"] if s != host][:20]
            urls += [f"https://{s}" for s in ins]
            if res["subdomains"]["out_of_scope"]:
                res["notes"].append("Kapsam dışı alt alan adları bulundu, taranmadı.")
        except RuntimeError as e:
            res["notes"].append(str(e)); print(e)
    if any(m.startswith("nuclei") for m in prof["modules"]):
        if urls:
            print(f"Zafiyet taraması ({len(urls)} adres)...")
            res["findings"] = nuclei_scan(scope, host, name, prof["rate"], urls)
        else:
            res["notes"].append("Web servisi bulunamadı, zafiyet taraması yapılmadı.")
            print("Web servisi bulunamadı, nuclei atlandı.")
    res["not_tested"] = [m for m in prof["modules"] if m == "webapp"]
    os.makedirs("reports", exist_ok=True)
    out = f"reports/{data['client'].replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M}.json"
    json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
    print(f"\nBitti. {len(res['ports'])} açık port, {len(res['findings'])} bulgu.")
    if res["subdomains"]:
        print(f"Alt alan adı: {len(res['subdomains']['in_scope'])} kapsamda, "
              f"{len(res['subdomains']['out_of_scope'])} kapsam dışı.")
    if res["ssl"]:
        if res["ssl"]["errors"]:
            print("SSL/başlık kontrolü tamamlanamadı:", "; ".join(res["ssl"]["errors"]))
        else:
            print(f"Eksik güvenlik başlığı: {len(res['ssl']['headers_missing'])}")
    print(f"Kayıt: {out}")

if __name__ == "__main__":
    main() 
