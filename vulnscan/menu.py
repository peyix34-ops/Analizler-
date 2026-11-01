import json, glob, os
from datetime import datetime
from .scope import Scope, ScopeError
from .profiles import load_profile
from .recon import port_scan
from .nuclei_mod import nuclei_scan

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
           "ports": [], "findings": []}
    if "ports" in prof["modules"]:
        print("Port taraması..."); res["ports"] = port_scan(scope, host)
    if any(m.startswith("nuclei") for m in prof["modules"]):
        print("Zafiyet taraması..."); res["findings"] = nuclei_scan(scope, host, name, prof["rate"])
    res["not_tested"] = [m for m in prof["modules"] if m in ("ssl", "subdomains", "webapp")]
    os.makedirs("reports", exist_ok=True)
    out = f"reports/{data['client'].replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M}.json"
    json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
    print(f"\nBitti. {len(res['ports'])} açık port, {len(res['findings'])} bulgu.\nKayıt: {out}")

if __name__ == "__main__":
    main()
