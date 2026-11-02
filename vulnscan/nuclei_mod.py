import json, shutil, subprocess

def nuclei_scan(scope, host, profile_name, rate, urls):
    scope.require(host)
    if not urls:
        return []
    if not shutil.which("nuclei"):
        raise RuntimeError("nuclei kurulu değil")
    sev = "critical,high" if profile_name == "basic" else "critical,high,medium,low"
    cmd = ["nuclei", "-severity", sev, "-rl", str(rate), "-jsonl", "-silent"]
    for u in urls:
        cmd += ["-u", u]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    out = []
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        out.append({"name": j["info"]["name"], "severity": j["info"]["severity"],
                    "url": j.get("matched-at"), "template": j.get("template-id")})
    return out
