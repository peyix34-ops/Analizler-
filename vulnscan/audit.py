import json, os, hashlib
from datetime import datetime, timezone

PATH = "logs/audit.jsonl"
ZERO = "0" * 64

def _last_hash():
    if not os.path.exists(PATH):
        return ZERO
    last = None
    for line in open(PATH):
        if line.strip():
            last = line
    return json.loads(last)["hash"] if last else ZERO

def log(event, **details):
    os.makedirs("logs", exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "event": event, **details, "prev": _last_hash()}
    body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    rec["hash"] = hashlib.sha256(body.encode()).hexdigest()
    with open(PATH, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def verify_chain():
    if not os.path.exists(PATH):
        return True, ""
    prev = ZERO
    for i, line in enumerate(open(PATH), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        h = rec.pop("hash", "")
        body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        if rec.get("prev") != prev or hashlib.sha256(body.encode()).hexdigest() != h:
            return False, f"satır {i}"
        prev = h
    return True, ""

def show(n=15):
    ok, msg = verify_chain()
    print("\nGünlük bütünlüğü:", "sağlam" if ok else f"BOZUK ({msg})")
    if not os.path.exists(PATH):
        print("Henüz kayıt yok."); return
    for l in [l for l in open(PATH) if l.strip()][-n:]:
        r = json.loads(l)
        extra = {k: v for k, v in r.items() if k not in ("ts", "event", "prev", "hash")}
        print(f"{r['ts']} {r['event']} {json.dumps(extra, ensure_ascii=False)[:110]}")
