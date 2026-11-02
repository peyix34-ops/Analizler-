import json, os, re
from datetime import date, timedelta
from .profiles import PROFILES

def ask(q, default=None):
    s = input(q + (f" [{default}]" if default else "") + ": ").strip()
    return s or default

def create():
    client = ask("Müşteri ad soyad / firma adı")
    host = re.sub(r"^https?://", "", ask("Site adresi (örn: ornek.com)").lower()).strip("/")
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        print("Geçersiz adres."); return
    prof = ask("Paket (basic/standard/deep)", "basic")
    if prof not in PROFILES:
        print("Geçersiz paket."); return
    days = int(ask("Kaç gün geçerli", "7"))
    signed = ask("İmzalı yetki formu alındı mı? (e/h)", "h").lower() == "e"
    deep_ok = False
    if prof == "deep":
        deep_ok = ask("Deep için yazılı onay formda var mı? (e/h)", "h").lower() == "e"
        sub_ok = ask("Alt alan adları da kapsamda mı? (e/h)", "h").lower() == "e"
    data = { 
        "client": client,
        "valid_from": date.today().isoformat(),
        "valid_until": (date.today() + timedelta(days=days)).isoformat(),
        "targets": [host] + ([f"*.{host}"] if sub_ok else []),
        "profile": prof,
        "authorized": signed,
        "deep_approved": deep_ok,
        "rate_limit": 50,
    }
    os.makedirs("scopes", exist_ok=True)
    path = "scopes/" + re.sub(r"[^a-z0-9]+", "_", client.lower()).strip("_") + ".json"
    json.dump(data, open(path, "w"), indent=2, ensure_ascii=False)
    print(f"Kaydedildi: {path}")
    if not signed:
        print("Uyarı: yetki formu yok, tarama başlamaz.")
