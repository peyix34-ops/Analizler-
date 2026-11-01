import json, shutil, subprocess

def nuclei_scan(scope, host, profile_name, rate):
    scope.require(host)
    if not shutil.which("nuclei"):
        raise RuntimeError("nuclei kurulu değil")
    sev = "critical,high" if profile_name == "basic" else "critical,high,medium,low"
    r = subprocess.run(
        ["nuclei", "-u", f"https://{host}", "-severity", sev,
         "-rl", str(rate), "-jsonl", "-silent"],
        capture_output=True, text=True, timeout=3600)
    out = []
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        out.append({"name": j["info"]["name"], "severity": j["info"]["severity"],
                    "url": j.get("matched-at"), "template": j.get("template-id")})
    return out
