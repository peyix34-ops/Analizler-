import shutil, subprocess

def find_subdomains(scope, domain):
    scope.require(domain)
    if not shutil.which("subfinder"):
        raise RuntimeError("subfinder kurulu değil")
    r = subprocess.run(["subfinder", "-d", domain, "-silent"],
                       capture_output=True, text=True, timeout=600)
    subs = sorted({s.strip().lower() for s in r.stdout.splitlines() if s.strip()})
    return {"in_scope": [s for s in subs if scope.allowed(s)],
            "out_of_scope": [s for s in subs if not scope.allowed(s)]}
