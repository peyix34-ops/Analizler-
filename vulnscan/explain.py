import json, glob, textwrap

PORTS = {
    21: ("FTP", "Dosya aktarım servisi. Şifreler çoğu zaman şifrelenmeden gider.", "Yüksek"),
    22: ("SSH", "Sunucuya uzaktan yönetim bağlantısı. Normal olabilir; sorun, şifresi zayıfsa ya da herkese açıksa.", "Orta"),
    23: ("Telnet", "Eski ve şifresiz uzaktan yönetim. Günümüzde açık olmaması gerekir.", "Yüksek"),
    25: ("SMTP", "E-posta gönderim servisi. Mail sunucusu varsa normaldir.", "Düşük"),
    53: ("DNS", "Alan adı çözümleme servisi. Yanlış ayarlanırsa kötüye kullanılabilir.", "Orta"),
    80: ("HTTP", "Web sitesi (şifresiz). Web sitesi için normal; sorun, HTTPS'e yönlendirilmiyorsa.", "Düşük"),
    110: ("POP3", "E-posta alma servisi, eski ve çoğu zaman şifresiz.", "Orta"),
    143: ("IMAP", "E-posta alma servisi. Şifrelenmemişse risklidir.", "Orta"),
    443: ("HTTPS", "Web sitesi (şifreli). Normal ve istenen durum.", "Düşük"),
    445: ("SMB", "Windows dosya paylaşımı. İnternete açık olmamalı, fidye yazılımları sık kullanır.", "Yüksek"),
    1433: ("MSSQL", "Veritabanı. İnternete açık olmamalı.", "Yüksek"),
    3306: ("MySQL", "Veritabanı. İnternete açık olmamalı, müşteri verisi burada durur.", "Yüksek"),
    3389: ("RDP", "Windows uzak masaüstü. Saldırganların çok denediği bir kapı.", "Yüksek"),
    5432: ("PostgreSQL", "Veritabanı. İnternete açık olmamalı.", "Yüksek"),
    6379: ("Redis", "Önbellek/veritabanı. Şifresiz açıksa ciddi risk.", "Yüksek"),
    8080: ("HTTP-alt", "Alternatif web portu. Genelde yönetim paneli ya da test sitesi olur, kontrol edilmeli.", "Orta"),
    8443: ("HTTPS-alt", "Alternatif şifreli web portu. Genelde yönetim paneli olur, kontrol edilmeli.", "Orta"),
    27017: ("MongoDB", "Veritabanı. Şifresiz açıksa veriler herkese açık olabilir.", "Yüksek"),
}

HEADER_INFO = {
    "HSTS": "Tarayıcıya 'bu siteye hep şifreli bağlan' demeyen site. Ziyaretçi yanlışlıkla şifresiz bağlanabilir.",
    "CSP": "Sitenin hangi kaynaklardan kod çalıştırabileceğini sınırlayan koruma eksik. Zararlı kod enjekte edilirse engellenmez.",
    "X-Frame-Options": "Siten başka bir sitenin içine gizlice gömülebilir. Kullanıcıyı farkında olmadan tıklatma (clickjacking) saldırısı yapılabilir.",
    "X-Content-Type-Options": "Tarayıcı dosya türünü tahmin edebilir. Bazı saldırılarda zararlı dosya yanlış çalıştırılabilir.",
}

SEV = {
    "critical": "Kritik: Hemen müdahale gerektirir, doğrudan sisteme zarar ya da veri sızıntısı olabilir.",
    "high": "Yüksek: Ciddi risk, kısa sürede ele alınmalı.",
    "medium": "Orta: Tek başına büyük zarar vermeyebilir ama başka açıklarla birleşebilir.",
    "low": "Düşük: Küçük risk, genelde bilgi sızdırma ya da zayıf yapılandırma.",
}

def w(t, indent="   "):
    print(textwrap.fill(t, width=58, initial_indent=indent, subsequent_indent=indent))

def title(t):
    print("\n" + "=" * 8 + " " + t + " " + "=" * 8)

def explain(r):
    print(f"\nMüşteri: {r['client']} | Hedef: {r['host']} | Paket: {r['profile']}")
    title("AÇIK PORTLAR")
    w("Port, sunucunun dışarıdan bağlantı kabul eden kapısıdır. Açık port tek başına açık değildir. Önemli olan kapının arkasındaki servisin güvenli olup olmadığıdır. Taranan aralık: ilk 1000 port.", "")
    if not r["ports"]:
        print("Açık port bulunamadı.")
    for p in r["ports"]:
        name, desc, risk = PORTS.get(p["port"], (p["service"].upper(), "Yaygın servis listemizde yok. Orada ne çalıştığı elle kontrol edilmeli.", "Belirsiz"))
        print(f"\n* Port {p['port']} ({name}) {p['service']} {p['version']}".rstrip())
        w(desc)
        w(f"Genel risk: {risk}")
    if r["ports"]:
        print()
        w("Not: Servisin sürüm numarası eskiyse bilinen açıkları olabilir. Bu araç sürümü açık veritabanıyla otomatik eşleştirmiyor, nuclei bazılarını yakalar.", "")
    title("SSL VE GÜVENLİK BAŞLIKLARI")
    s = r.get("ssl")
    if not s:
        print("Bu pakette yapılmadı.")
    else:
        if not s["https_available"]:
            w("Site HTTPS (şifreli bağlantı) sunmuyor ya da 443 portuna ulaşılamadı. Ziyaretçi ile site arasındaki bilgiler (şifre, form) yolda okunabilir.", "")
        if s["cert"]:
            d = s["cert"]["days_left"]
            if d < 0:
                w(f"Sertifikanın süresi {-d} gün önce dolmuş. Tarayıcılar ziyaretçiye uyarı gösterir.", "")
            elif d < 30:
                w(f"Sertifika {d} gün sonra bitiyor. Yenilenmezse site uyarı verir.", "")
            else:
                w(f"Sertifika geçerli, {d} gün kaldı.", "")
            if s["cert"]["tls"] in ("TLSv1", "TLSv1.1"):
                w(f"Eski şifreleme sürümü kullanılıyor ({s['cert']['tls']}). Güvenli sayılmıyor.", "")
            else:
                w(f"Şifreleme sürümü: {s['cert']['tls']} (güncel).", "")
        for e in s["errors"]:
            w("Uyarı: " + e, "")
        for m in s["headers_missing"]:
            print(f"\n* Eksik: {m}")
            for k, v in HEADER_INFO.items():
                if m.startswith(k):
                    w(v)
    title("ALT ALAN ADLARI")
    sd = r.get("subdomains")
    if not sd:
        print("Bu pakette yapılmadı.")
    else:
        w("Alt alan adı, ana sitenin yan adresleridir (blog.ornek.com gibi). Unutulmuş test siteleri sık açık çıkar.", "")
        print(f"\nKapsamda: {len(sd['in_scope'])} adet")
        for x in sd["in_scope"][:15]:
            print("  -", x)
        if sd["out_of_scope"]:
            print(f"\nKapsam dışı: {len(sd['out_of_scope'])} adet (taranmadı)")
            w("Bunlar müşterinin yetki verdiği listede yok. İzinsiz taramayız, sadece müşteriye bildirilir.")
             from .web_mod import explain_web
explain_web(r.get("web"), w, title)

    title("ZAFİYET BULGULARI (NUCLEI)")
    if not r["findings"]:
        w("Nuclei'nin baktığı şablonlarda bulgu çıkmadı. Bu 'site güvenli' demek değildir, sadece bilinen açık kalıpları tarandı.", "")
    for f in r["findings"]:
        print(f"\n* [{f['severity'].upper()}] {f['name']}")
        print(f"  Adres: {f['url']}")
        w(SEV.get(f["severity"], ""))
    if r["findings"]:
        print()
        w("Uyarı: Bunlar otomatik tespittir. Müşteriye vermeden önce elle doğrula, yanlış pozitif olabilir.", "")
    title("TEST EDİLMEYENLER VE NOTLAR")
    for n in r.get("not_tested", []):
        print("- Test edilmedi:", n)
    for n in r.get("notes", []):
        print("-", n)
    if not r.get("not_tested") and not r.get("notes"):
        print("Ek not yok.")

def main():
    files = sorted(glob.glob("reports/*.json"))
    if not files:
        print("reports/ içinde rapor yok. Önce tarama yap."); return
    print("\nRaporlar:")
    for i, f in enumerate(files, 1):
        print(f"  {i}) {f}")
    s = input("Seçim (Enter = en son): ").strip()
    explain(json.load(open(files[int(s) - 1] if s else files[-1])))

if __name__ == "__main__":
    main()
