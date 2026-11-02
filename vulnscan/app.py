from . import menu, newclient

def main():
    while True:
        print("\n=== VulnScan ===")
        print("1) Yeni müşteri")
        print("2) Tarama başlat")
        print("0) Çıkış")
        c = input("Seçim: ").strip()
        if c == "1":
            newclient.create()
        elif c == "2":
            menu.main()
        elif c == "0":
            break

if __name__ == "__main__":
    main()
