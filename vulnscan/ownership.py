import json, glob, secrets
from datetime import datetime
from .net import fetch, doh_txt
from .scope import Scope, ScopeError
from . import audit

PUBLIC_TEST = {"scanme.nmap.org"}

def new_token():
    return secrets.token_hex(8)

def is_verified(data):
    if data["targets"] and all(t in PUBLIC_TEST for t in data["targets"]):
        return True, "public_test"
    o = data.get("ownership") or {}
    return bool(o.get("verified")), o.get("method")

def dns_check(host, token):
    try:
        return any(f"vulnscan-verify={token}" in t for t in doh_txt(f"_vulnscan.{host}"))
    except Exception as e:
        print("DNS sorgusu yapılamadı:", e)
        return False

def file_check(scope, host, token):
    scope.require(host)
    for scheme in ("https", "http"):
        try:
            st, _, body = fetch(host, "/.well-known/vulnscan-verify.txt", scheme)
        except Exception:
            continue
        if st == 200 and f"vulnscan-verify={token}" in body.decode("utf-8", "ignore"):
            return True
    return False

def verify_menu():
    files = sorted(glob.glob("scopes/*.json"))
    if not files:
        print("scopes/ içinde müşteri dosyası yok."); return
    for i, f in enumerate(files, 1):
        print(f"  {i}) {f}")
    path = files[int(input("Seçim: ")) - 1]
    data = json.load(open(path))
    ok, m = is_verified(data)
    if ok:
        print(f"Zaten doğrulanmış ({m})."); return
    o = data.get("ownership") or {}
    token = o.get("token") or new_token()
    host = [t for t in data["targets"] if "*" not in t][0]
    print(f"\nMüşteri: {data['client']} | Alan adı: {host}")
    print(f"Doğrulama kodu: vulnscan-verify={token}")
    print("\n1) DNS kaydı\n2) Dosya\n3) İmzalı form (elle teyit)")
    c = input("Yöntem: ").strip()
    ok, method, note = False, None, ""
    if c == "1":
        print(f"\nMüşteri şu TXT kaydını eklemeli:\n  Ad: _vulnscan.{host}\n  Değer: vulnscan-verify={token}")
        input("Eklendiyse Enter'a bas...")
        ok, method = dns_check(host, token), "dns"
    elif c == "2":
        print(f"\nMüşteri şu adrese, içinde sadece şu metin olan dosya koymalı:\n  /.well-known/vulnscan-verify.txt\n  İçerik: vulnscan-verify={token}")
        input("Konulduysa Enter'a bas...")
        try:
            ok, method = file_check(Scope(path), host, token), "file"
        except ScopeError as e:
            print("Durduruldu:", e); return
    elif c == "3":
        print("\nAlan adı sahibinin imzaladığı form elinde mi ve sahibi WHOIS/hosting hesabından teyit ettin mi?")
        if input("(e/h): ").strip().lower() == "e":
            note = input("Form kaydı için kısa not (dosya adı/tarih): ")
            ok, method = True, "signed_form"
    else:
        return
    if ok:
        data["ownership"] = {"method": method, "token": token, "verified": True,
                             "verified_at": datetime.now().isoformat(timespec="minutes")}
        if note:
            data["ownership"]["note"] = note
        audit.log("ownership_verified", client=data["client"], host=host, method=method, note=note)
        print("Sahiplik doğrulandı:", method)
    else:
        data["ownership"] = {**o, "token": token, "verified": False}
        audit.log("ownership_failed", client=data["client"], host=host, method=method)
        print("Doğrulanamadı. Kayıt henüz yayılmamış olabilir, biraz sonra tekrar dene.")
    json.dump(data, open(path, "w"), indent=2, ensure_ascii=False)
