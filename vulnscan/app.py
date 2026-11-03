from . import menu, newclient, explain, ownership, audit

def main():
    while True:
        print("\n=== VulnScan ===")
        print("1) Yeni müşteri")
        print("2) Tarama başlat")
        print("3) Raporu açıkla")
        print("4) Sahiplik doğrula")
        print("5) Kayıt günlüğü")
        print("0) Çıkış")
        c = input("Seçim: ").strip()
        if c == "1":
            newclient.create()
        elif c == "2":
            menu.main()
        elif c == "3":
            explain.main()
        elif c == "4":
            ownership.verify_menu()
        elif c == "5":
            audit.show()
        elif c == "0":
            break

if __name__ == "__main__":
    main()
