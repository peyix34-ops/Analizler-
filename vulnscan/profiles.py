PROFILES = {
    "basic":    {"modules": ["ports", "ssl", "nuclei_critical"], "rate": 50},
    "standard": {"modules": ["ports", "ssl", "subdomains", "nuclei_all"], "rate": 100},
    "deep":     {"modules": ["ports", "ssl", "subdomains", "nuclei_all", "webapp"], "rate": 30},
}

def load_profile(scope_data):
    name = scope_data.get("profile", "basic")
    if name not in PROFILES:
        raise ValueError(f"Bilinmeyen profil: {name}")
    if name == "deep" and not scope_data.get("deep_approved"):
        raise PermissionError("Deep için müşteri onayı yok (deep_approved).")
    p = dict(PROFILES[name])
    p["rate"] = min(p["rate"], scope_data.get("rate_limit", p["rate"]))
    return name, p
