from flask import Flask, render_template, request, jsonify
import requests
import socket
import tldextract
from datetime import datetime

# whois is optional
try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

app = Flask(__name__)

# ---------------------------------------
# Website purpose mapping
# ---------------------------------------
WEBSITE_PURPOSE = {
    "google.com": "Search engine and online services",
    "youtube.com": "Video streaming and content sharing platform",
    "facebook.com": "Social networking and communication",
    "instagram.com": "Photo and video sharing social media",
    "amazon.com": "Online shopping and e-commerce marketplace",
    "flipkart.com": "Indian e-commerce shopping platform",
    "twitter.com": "Microblogging and social networking",
    "x.com": "Microblogging and social networking",
    "netflix.com": "Online movie and web-series streaming",
    "paypal.com": "Online payment service",
    "github.com": "Software development and code hosting",
    "linkedin.com": "Professional social networking",
    "microsoft.com": "Software, cloud and technology services",
    "apple.com": "Technology, devices and online services",
    "wikipedia.org": "Online encyclopedia",
    "hdfcbank.com": "Banking and financial services",
    "icicibank.com": "Banking and financial services",
    "sbi.co.in": "Banking and financial services"
}


# ---------------------------------------
# Return purpose
# ---------------------------------------
def get_website_purpose(domain):
    return WEBSITE_PURPOSE.get(domain.lower(), "General website / No specific category")


SUSPICIOUS_WORDS = ["login", "verify", "account", "update", "bank", "banking", "secure", "free", "bonus", "offer"]
UNTRUSTED_EXT = [".tk", ".ml", ".ga", ".cf", ".gq"]


# ---------------------------------------
# BRAND IMPERSONATION
# ---------------------------------------
def is_brand_impersonation(domain):
    BRANDS = ["google", "amazon", "facebook", "instagram", "paypal", "sbi", "hdfc", "flipkart"]

    domain_name = domain.split(".")[0].lower()
    replacements = {"0": "o", "1": "l", "3": "e", "5": "s", "9": "g"}

    normalized = domain_name
    for num, letter in replacements.items():
        normalized = normalized.replace(num, letter)

    for brand in BRANDS:
        if domain_name == brand:
            return False
        if normalized == brand:
            return True
        if brand in domain_name and domain_name != brand:
            return True

    return False


# ---------------------------------------
# URL NORMALIZATION
# ---------------------------------------
def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith("http://") and not raw.startswith("https://"):
        return "https://" + raw
    return raw


# ---------------------------------------
# EXTRACT DOMAIN
# ---------------------------------------
def extract_domain(url):
    try:
        p = tldextract.extract(url)
        return p.registered_domain if p.registered_domain else url
    except:
        return url


# ---------------------------------------
# DNS CHECK
# ---------------------------------------
def domain_resolves(domain):
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except:
        return False, None


# ---------------------------------------
# REACHABILITY (HEAD + GET fallback)
# ---------------------------------------
def check_reachable(url):
    headers = {"User-Agent": "Mozilla/5.0 GenuineChecker"}
    try:
        r = requests.head(url, headers=headers, timeout=6, allow_redirects=True)
        if r.status_code >= 400:
            r2 = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            return (200 <= r2.status_code < 400, "GET fallback", r2.status_code)
        return (200 <= r.status_code < 400, "HEAD", r.status_code)
    except:
        return (False, "Connection failed", -1)


# ---------------------------------------
# RDAP BACKUP
# ---------------------------------------
def get_rdap_info(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return None, None

        data = r.json()
        creation = None
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                creation = ev.get("eventDate")

        if creation:
            dt = datetime.fromisoformat(creation.replace("Z", ""))
            return dt.strftime("%d %b %Y"), (datetime.utcnow() - dt).days

        return None, None
    except:
        return None, None


# ---------------------------------------
# WHOIS + RDAP COMBINED
# ---------------------------------------
def get_registrar_info(domain):
    readable = None
    age_days = None

    # Try WHOIS first
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            creation = w.creation_date

            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                if isinstance(creation, str):
                    try:
                        creation_dt = datetime.fromisoformat(creation)
                    except:
                        try:
                            creation_dt = datetime.strptime(creation[:19], "%Y-%m-%d %H:%M:%S")
                        except:
                            creation_dt = None
                else:
                    creation_dt = creation

                if creation_dt:
                    readable = creation_dt.strftime("%d %b %Y")
                    age_days = (datetime.utcnow() - creation_dt).days
        except:
            pass

    # If WHOIS fails, use RDAP
    if not readable:
        readable, age_days = get_rdap_info(domain)

    return readable, age_days


# ---------------------------------------
# TRUST SCORE
# ---------------------------------------
def compute_trust_score(d):
    if not d["reachable"]:
        return 0
    score = 100
    if d["suspicious_keyword"]:
        score -= 30
    if d["untrusted_extension"]:
        score -= 25
    if d["brand_impersonation"]:
        score -= 40
    if not d["dns_resolves"]:
        return 0
    if not d["https"]:
        score -= 20
    if d["domain_age_days"] is not None:
        if d["domain_age_days"] < 30:
            score -= 25
        elif d["domain_age_days"] < 365:
            score -= 10
    return max(0, min(score, 100))


# ---------------------------------------
# MAIN ANALYSIS FUNCTION
# ---------------------------------------
def analyze_url(raw):
    raw = raw.strip()
    if not raw:
        return {"status": "Scam", "reason": "Empty URL", "trust_score": 0}

    url = normalize_url(raw)
    domain = extract_domain(url)
    lower = raw.lower()

    details = {
        "suspicious_keyword": any(w in lower for w in SUSPICIOUS_WORDS),
        "untrusted_extension": any(domain.endswith(ext) for ext in UNTRUSTED_EXT),
        "brand_impersonation": is_brand_impersonation(domain),
        "https": url.startswith("https://"),
        "dns_resolves": False,
        "reachable": False,
        "domain_age_days": None
    }

    dns_ok, ip = domain_resolves(domain)
    details["dns_resolves"] = dns_ok

    reg_date, age_days = get_registrar_info(domain)
    details["domain_age_days"] = age_days

    reachable, method, code = check_reachable(url)
    details["reachable"] = reachable

    # STATUS DECISION
    if details["suspicious_keyword"]:
        status = "Scam"
        reason = "Suspicious keywords found"
    elif details["untrusted_extension"]:
        status = "Scam"
        reason = "Untrusted domain extension"
    elif details["brand_impersonation"]:
        status = "Scam"
        reason = "Brand impersonation detected"
    elif not dns_ok:
        status = "Scam"
        reason = "DNS resolution failed"
    elif not reachable:
        status = "Scam"
        reason = "Server unreachable"
    elif not details["https"]:
        status = "Scam"
        reason = "HTTPS missing"
    elif age_days is not None and age_days < 365:
        status = "Scam"
        reason = f"Domain too new ({age_days} days)"
    else:
        status = "Genuine"
        reason = f"Website reachable ({method}, {code})"

    trust = compute_trust_score(details)

    purpose = get_website_purpose(domain) if status == "Genuine" else None

    return {
        "url": raw,
        "domain_name": domain,
        "ip": ip,
        "registrar_date": reg_date,
        "domain_age_days": age_days,
        "trust_score": trust,
        "status": status,
        "reason": reason,
        "purpose": purpose
    }


# ---------------------------------------
# ROUTES
# ---------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    url = request.get_json().get("url")
    return jsonify(analyze_url(url))


if __name__ == "__main__":
    app.run(debug=True)
