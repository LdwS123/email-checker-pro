#!/usr/bin/env python3
"""
Email Checker Pro — Web App
7 checks: Format, DNS/MX, Catch-all, SMTP, Gravatar, GitHub, Blacklist
Run: python3 email_checker_app.py
     GH_TOKEN=ghp_xxx python3 email_checker_app.py   (enable GitHub check)
Open: http://localhost:5050
"""
import re, smtplib, time, json, hashlib, os
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template_string, request, jsonify, Response
import dns.resolver
import requests as http_requests

app = Flask(__name__)

GH_TOKEN = os.environ.get("GH_TOKEN", "")

# ── State ───────────────────────────────────────────────────
jobs = {}
job_lock = Lock()
job_counter = 0

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

mx_cache = {}
catchall_cache = {}
blacklist_cache = {}
smtp_blocked = False  # Auto-detect: set True if port 25 is unreachable

BLACKLISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
]


# ── Checks ──────────────────────────────────────────────────
def get_mx(domain):
    if domain in mx_cache:
        return mx_cache[domain]
    try:
        records = dns.resolver.resolve(domain, "MX")
        mx = sorted(records, key=lambda r: r.preference)
        host = str(mx[0].exchange).rstrip(".")
        mx_cache[domain] = host
        return host
    except Exception:
        mx_cache[domain] = None
        return None


def check_catchall(domain):
    if domain in catchall_cache:
        return catchall_cache[domain]
    mx = get_mx(domain)
    if not mx:
        catchall_cache[domain] = None
        return None
    try:
        with smtplib.SMTP(mx, 25, timeout=8) as smtp:
            smtp.ehlo("check.example.com")
            smtp.mail("test@example.com")
            code, _ = smtp.rcpt(f"zzzfake9876nonexist@{domain}")
            result = code == 250
            catchall_cache[domain] = result
            return result
    except Exception:
        catchall_cache[domain] = None
        return None


# ── API-based verification (fallback when port 25 blocked) ──
api_cache = {}

def check_email_api(email):
    """Use free APIs to verify email when SMTP is blocked."""
    if email in api_cache:
        return api_cache[email]

    result = {"deliverable": None, "disposable": False, "role": False, "provider": None, "domain_age": None}

    # Try mailcheck.ai first (gives provider info + domain age)
    try:
        r = http_requests.get(f"https://api.mailcheck.ai/email/{email}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            result["disposable"] = data.get("disposable", False)
            result["role"] = data.get("role_account", False)
            result["domain_age"] = data.get("domain_age_in_days")
            providers = data.get("mx_providers", [])
            if providers:
                result["provider"] = providers[0].get("slug", "")
            result["deliverable"] = not data.get("disposable", False) and data.get("mx", False)
    except Exception:
        pass

    # Try disify.com as second source
    try:
        r = http_requests.get(f"https://disify.com/api/email/{email}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            if result["deliverable"] is None:
                result["deliverable"] = data.get("format", False) and data.get("dns", False)
            if data.get("disposable", False):
                result["disposable"] = True
            if data.get("role", False):
                result["role"] = True
    except Exception:
        pass

    api_cache[email] = result
    return result


def check_gravatar(email):
    """Check if email has a Gravatar profile."""
    try:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        r = http_requests.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def check_github_commits(email):
    """Check if email has public GitHub commits."""
    if not GH_TOKEN:
        return None
    try:
        r = http_requests.get(
            f"https://api.github.com/search/commits?q=author-email:{email}",
            headers={
                "Authorization": f"token {GH_TOKEN}",
                "Accept": "application/vnd.github.cloak-preview+json",
            },
            timeout=10,
        )
        if r.status_code == 200:
            count = r.json().get("total_count", 0)
            return count
        return None
    except Exception:
        return None


def check_github_profile(email):
    """Find GitHub profile associated with this email."""
    if not GH_TOKEN:
        return None
    try:
        r = http_requests.get(
            f"https://api.github.com/search/users?q={email}+in:email",
            headers={"Authorization": f"token {GH_TOKEN}"},
            timeout=10,
        )
        if r.status_code == 200:
            items = r.json().get("items", [])
            if items:
                u = items[0]
                return {"login": u["login"], "url": u["html_url"],
                        "avatar": u.get("avatar_url", ""), "name": u.get("name", "")}
        return None
    except Exception:
        return None


def build_linkedin_url(email):
    """Generate a LinkedIn search URL from the email."""
    local = email.split("@")[0]
    domain = email.split("@")[1]
    company = domain.split(".")[0]
    # Extract name parts from local (e.g. john.doe -> John Doe)
    parts = re.split(r"[._\-]", local)
    # Filter out numbers and very short parts
    name_parts = [p.capitalize() for p in parts if len(p) > 1 and not p.isdigit()]
    if not name_parts:
        return None
    query = "+".join(name_parts + [company])
    return f"https://www.linkedin.com/search/results/people/?keywords={query}"


def check_blacklists(domain):
    """Check domain against DNSBL blacklists."""
    if domain in blacklist_cache:
        return blacklist_cache[domain]
    listed_on = []
    checked = 0
    for bl in BLACKLISTS:
        try:
            dns.resolver.resolve(f"{domain}.{bl}", "A")
            listed_on.append(bl)
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
        checked += 1
    result = {"checked": checked, "listed_on": listed_on, "clean": len(listed_on) == 0}
    blacklist_cache[domain] = result
    return result


def compute_score(result):
    """Compute a confidence score 0-100."""
    score = 0

    # Format valid: +10
    if result["format"]:
        score += 10

    # DNS/MX valid: +15
    if result["dns"]:
        score += 15

    # SMTP valid: +40 (biggest signal), API valid: +30
    if result["smtp"] is True:
        if result["catchall"]:
            score += 20  # Less certain for catch-all
        elif result.get("reason") == "Verifie via API":
            score += 30  # API confirmation (less certain than SMTP)
        else:
            score += 40  # Confirmed by SMTP server

    # Gravatar: +10
    if result.get("gravatar"):
        score += 10

    # GitHub commits: +15 (strong signal)
    gh = result.get("github_commits")
    if gh is not None and gh > 0:
        score += 15

    # GitHub profile found: +10
    if result.get("github_profile"):
        score += 10

    # Blacklist clean: +10
    bl = result.get("blacklist", {})
    if bl.get("clean"):
        score += 10
    elif bl.get("listed_on"):
        score -= 20  # Penalize blacklisted domains

    return min(score, 100)


def verify_single(email):
    email = email.strip().lower()
    result = {
        "email": email,
        "format": False,
        "dns": False,
        "mx": None,
        "catchall": None,
        "smtp": None,
        "gravatar": False,
        "github_commits": None,
        "blacklist": {},
        "status": "invalid",
        "score": 0,
        "checks": [],
    }

    # 1. Format
    if not EMAIL_RE.fullmatch(email):
        result["reason"] = "Format invalide"
        result["checks"].append({"name": "Format", "pass": False, "detail": "Format email invalide"})
        return result
    result["format"] = True
    result["checks"].append({"name": "Format", "pass": True, "detail": "Format valide"})

    domain = email.split("@")[1]

    # 2. DNS/MX
    mx = get_mx(domain)
    if not mx:
        result["reason"] = "Domaine introuvable (pas de MX)"
        result["checks"].append({"name": "DNS/MX", "pass": False, "detail": "Pas de serveur mail"})
        result["score"] = compute_score(result)
        return result
    result["dns"] = True
    result["mx"] = mx
    result["checks"].append({"name": "DNS/MX", "pass": True, "detail": mx})

    # 3. Catch-all + 4. SMTP — skip if port 25 is known to be blocked
    global smtp_blocked
    smtp_ok = False

    if not smtp_blocked:
        # 3. Catch-all
        catchall = check_catchall(domain)
        result["catchall"] = catchall
        if catchall:
            result["checks"].append({"name": "Catch-all", "pass": None, "detail": "Domaine accepte tout"})
        elif catchall is False:
            result["checks"].append({"name": "Catch-all", "pass": True, "detail": "Domaine filtre les emails"})
        else:
            result["checks"].append({"name": "Catch-all", "pass": None, "detail": "Non testable"})

        # 4. SMTP direct
        try:
            with smtplib.SMTP(mx, 25, timeout=8) as smtp:
                smtp.ehlo("check.example.com")
                smtp.mail("test@example.com")
                code, msg = smtp.rcpt(email)
                smtp_ok = True
                if code == 250:
                    result["smtp"] = True
                    if catchall:
                        result["status"] = "catch-all"
                        result["reason"] = "Catch-all: accepte tout"
                        result["checks"].append({"name": "SMTP", "pass": None, "detail": "Accepte (catch-all)"})
                    else:
                        result["status"] = "valid"
                        result["reason"] = "Boite mail confirmee"
                        result["checks"].append({"name": "SMTP", "pass": True, "detail": "Boite mail existe (250)"})
                else:
                    result["smtp"] = False
                    result["status"] = "invalid"
                    result["reason"] = f"Rejete (code {code})"
                    result["checks"].append({"name": "SMTP", "pass": False, "detail": f"Rejete ({code})"})
        except smtplib.SMTPServerDisconnected:
            result["checks"].append({"name": "SMTP", "pass": None, "detail": "Connexion coupee"})
        except OSError as e:
            if "unreachable" in str(e).lower() or "Network is unreachable" in str(e):
                smtp_blocked = True  # Auto-detect: port 25 blocked on this host
            # Will use API fallback below
        except Exception:
            pass
    else:
        # Port 25 blocked — skip SMTP entirely
        result["checks"].append({"name": "Catch-all", "pass": None, "detail": "SMTP non dispo (cloud)"})

    # 4b. API fallback if SMTP failed/blocked
    if not smtp_ok:
        api = check_email_api(email)
        detail_parts = []
        if api.get("provider"):
            detail_parts.append(f"Provider: {api['provider']}")
        if api.get("domain_age") is not None:
            age_years = round(api["domain_age"] / 365, 1)
            detail_parts.append(f"Domaine: {age_years}ans")
        if api.get("disposable"):
            detail_parts.append("JETABLE")
        if api.get("role"):
            detail_parts.append("role-email")

        if api.get("deliverable") is True and not api.get("disposable"):
            result["smtp"] = True
            result["status"] = "valid"
            result["reason"] = "Verifie via API"
            detail = "Deliverable (API) — " + ", ".join(detail_parts) if detail_parts else "Deliverable (API)"
            result["checks"].append({"name": "SMTP/API", "pass": True, "detail": detail})
        elif api.get("disposable"):
            result["smtp"] = False
            result["status"] = "invalid"
            result["reason"] = "Email jetable"
            result["checks"].append({"name": "SMTP/API", "pass": False, "detail": "Email jetable (disposable)"})
        else:
            result["status"] = "unknown"
            result["reason"] = "Non verifiable"
            detail = "Port 25 bloque — " + ", ".join(detail_parts) if detail_parts else "Port 25 bloque"
            result["checks"].append({"name": "SMTP/API", "pass": None, "detail": detail})

    # 5-9. Gravatar + GitHub commits + GitHub profile + Blacklist — run in parallel
    with ThreadPoolExecutor(max_workers=5) as pool:
        fut_grav = pool.submit(check_gravatar, email)
        fut_gh = pool.submit(check_github_commits, email)
        fut_ghp = pool.submit(check_github_profile, email)
        fut_bl = pool.submit(check_blacklists, domain)

        grav = fut_grav.result()
        gh = fut_gh.result()
        ghp = fut_ghp.result()
        bl = fut_bl.result()

    # 5. Gravatar
    result["gravatar"] = grav
    result["checks"].append({
        "name": "Gravatar",
        "pass": grav,
        "detail": "Profil trouve" if grav else "Pas de profil",
    })

    # 6. GitHub commits
    result["github_commits"] = gh
    if gh is not None:
        result["checks"].append({
            "name": "GitHub Commits",
            "pass": gh > 0,
            "detail": f"{gh} commits" if gh > 0 else "Aucun commit",
        })
    else:
        result["checks"].append({"name": "GitHub Commits", "pass": None, "detail": "Non verifie (pas de token)"})

    # 7. GitHub profile
    if ghp:
        result["github_profile"] = ghp
        result["checks"].append({
            "name": "GitHub Profil",
            "pass": True,
            "detail": f"@{ghp['login']}",
            "url": ghp["url"],
        })
    else:
        result["checks"].append({"name": "GitHub Profil", "pass": False, "detail": "Pas de profil public"})

    # 8. LinkedIn search
    li_url = build_linkedin_url(email)
    if li_url:
        result["linkedin_url"] = li_url
        local = email.split("@")[0]
        name_parts = re.split(r"[._\-]", local)
        name_display = " ".join(p.capitalize() for p in name_parts if len(p) > 1 and not p.isdigit())
        result["checks"].append({
            "name": "LinkedIn",
            "pass": None,
            "detail": f"Rechercher {name_display}",
            "url": li_url,
        })

    # 9. Blacklist
    result["blacklist"] = bl
    if bl["clean"]:
        result["checks"].append({"name": "Blacklist", "pass": True, "detail": f"Clean ({bl['checked']}/{bl['checked']})"})
    else:
        result["checks"].append({"name": "Blacklist", "pass": False, "detail": f"Liste sur {', '.join(bl['listed_on'])}"})

    # Score
    result["score"] = compute_score(result)

    return result


def verify_with_timeout(email, timeout=45):
    """Run verify_single with a hard timeout."""
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(verify_single, email)
        try:
            return fut.result(timeout=timeout)
        except Exception:
            return {
                "email": email.strip().lower(),
                "format": True, "dns": False, "mx": None,
                "catchall": None, "smtp": None, "gravatar": False,
                "github_commits": None, "blacklist": {},
                "status": "unknown", "score": 0,
                "checks": [{"name": "Timeout", "pass": False,
                             "detail": f"Verification expirée ({timeout}s)"}],
                "reason": "Timeout",
            }


def process_job(job_id, emails):
    """Process emails in parallel — up to 5 at a time, 30s max per email."""
    def _do(email):
        result = verify_with_timeout(email, timeout=45)
        with job_lock:
            jobs[job_id]["results"].append(result)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = [pool.submit(_do, e) for e in emails]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
    with job_lock:
        jobs[job_id]["done"] = True


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/check", methods=["POST"])
def check_emails():
    global job_counter
    data = request.json
    raw = data.get("emails", "")
    emails = EMAIL_RE.findall(raw)
    emails = list(dict.fromkeys(emails))
    if not emails:
        return jsonify({"error": "Aucun email valide trouve"}), 400

    with job_lock:
        job_counter += 1
        job_id = str(job_counter)
        jobs[job_id] = {"emails": emails, "results": [], "done": False}

    thread = Thread(target=process_job, args=(job_id, emails), daemon=True)
    thread.start()
    return jsonify({"job_id": job_id, "total": len(emails)})


@app.route("/api/status/<job_id>")
def job_status(job_id):
    with job_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({
            "total": len(job["emails"]),
            "checked": len(job["results"]),
            "done": job["done"],
            "results": job["results"],
        })


@app.route("/api/export/<job_id>")
def export_csv(job_id):
    with job_lock:
        job = jobs.get(job_id)
        if not job:
            return "Job not found", 404
        lines = ["email,status,score,mx,catchall,gravatar,github_commits,blacklist_clean,reason"]
        for r in job["results"]:
            reason = str(r.get("reason", "")).replace(",", ";")
            lines.append(",".join([
                r["email"], r["status"], str(r["score"]),
                str(r.get("mx", "")), str(r.get("catchall", "")),
                str(r.get("gravatar", "")), str(r.get("github_commits", "")),
                str(r.get("blacklist", {}).get("clean", "")), reason,
            ]))
    csv_data = "\n".join(lines)
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=verified_emails.csv"})


HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Checker Pro</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f5f7; color: #1d1d1f; min-height: 100vh;
  }
  .container { max-width: 960px; margin: 0 auto; padding: 40px 20px; }
  h1 { font-size: 2.2rem; font-weight: 700; margin-bottom: 6px; color: #1d1d1f; }
  h1 span { color: #0071e3; }
  .subtitle { color: #86868b; margin-bottom: 28px; font-size: 0.95rem; }

  textarea {
    width: 100%; height: 150px; background: #fff; border: 2px solid #d2d2d7;
    border-radius: 12px; padding: 16px; color: #1d1d1f; font-size: 14px;
    font-family: 'SF Mono', Monaco, Consolas, monospace; resize: vertical;
    outline: none; transition: border-color 0.2s;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  textarea:focus { border-color: #0071e3; }
  textarea::placeholder { color: #aeaeb2; }

  .actions { display: flex; gap: 10px; margin-top: 16px; align-items: center; flex-wrap: wrap; }
  button, label.btn {
    padding: 12px 28px; border-radius: 10px; border: none; font-size: 15px;
    font-weight: 600; cursor: pointer; transition: all 0.2s; display: inline-flex;
    align-items: center; gap: 6px;
  }
  .btn-check { background: #0071e3; color: #fff; }
  .btn-check:hover { background: #0077ed; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,113,227,0.3); }
  .btn-check:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }
  .btn-csv { background: #fff; color: #1d1d1f; border: 2px solid #d2d2d7; }
  .btn-csv:hover { background: #f0f0f0; }
  .btn-export { background: #34c759; color: #fff; }
  .btn-export:hover { background: #2db84e; }
  .btn-export:disabled { opacity: 0.3; cursor: not-allowed; }
  .btn-clear { background: #ff3b30; color: #fff; padding: 12px 20px; }
  .btn-clear:hover { background: #e0352b; }
  .count-info { color: #86868b; font-size: 14px; margin-left: auto; }
  #csvFile { display: none; }

  .progress-bar {
    margin-top: 20px; height: 6px; background: #e5e5ea; border-radius: 3px;
    overflow: hidden; display: none;
  }
  .progress-bar .fill {
    height: 100%; background: linear-gradient(90deg, #0071e3, #5ac8fa);
    border-radius: 3px; transition: width 0.3s; width: 0%;
  }
  .progress-text {
    margin-top: 8px; font-size: 13px; color: #86868b; display: none; text-align: center;
  }

  .stats { display: none; gap: 14px; margin-top: 20px; flex-wrap: wrap; }
  .stat {
    background: #fff; border: 1px solid #e5e5ea; border-radius: 12px;
    padding: 16px 22px; min-width: 110px; text-align: center; flex: 1;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  .stat .num { font-size: 2rem; font-weight: 700; }
  .stat .label { font-size: 0.78rem; color: #86868b; margin-top: 4px; }
  .stat.valid .num { color: #34c759; }
  .stat.invalid .num { color: #ff3b30; }
  .stat.catchall .num { color: #ff9500; }
  .stat.unknown .num { color: #8e8e93; }

  .results { margin-top: 28px; }

  .result-card {
    background: #fff; border: 1px solid #e5e5ea; border-radius: 14px;
    padding: 20px; margin-bottom: 12px; animation: fadeIn 0.3s ease;
    box-shadow: 0 1px 4px rgba(0,0,0,0.05);
  }
  .result-card.status-valid { border-left: 4px solid #34c759; }
  .result-card.status-invalid { border-left: 4px solid #ff3b30; }
  .result-card.status-catch-all { border-left: 4px solid #ff9500; }
  .result-card.status-unknown { border-left: 4px solid #8e8e93; }

  @keyframes fadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; } }

  .result-top { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .badge {
    padding: 5px 12px; border-radius: 8px; font-size: 11px; font-weight: 700;
    min-width: 80px; text-align: center; text-transform: uppercase; letter-spacing: 0.5px;
  }
  .badge.valid { background: #e8f8ee; color: #1a7f37; }
  .badge.invalid { background: #ffeaeb; color: #d1242f; }
  .badge.catch-all { background: #fff4e0; color: #b35c00; }
  .badge.unknown { background: #f0f0f0; color: #636366; }

  .email-text {
    font-family: 'SF Mono', Monaco, Consolas, monospace; flex: 1;
    font-size: 15px; font-weight: 600; color: #1d1d1f;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .score-circle {
    width: 48px; height: 48px; border-radius: 50%; display: flex;
    align-items: center; justify-content: center; font-weight: 800;
    font-size: 14px; flex-shrink: 0;
  }
  .score-circle.high { background: #e8f8ee; color: #1a7f37; }
  .score-circle.mid { background: #fff4e0; color: #b35c00; }
  .score-circle.low { background: #ffeaeb; color: #d1242f; }

  .checks-grid {
    display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;
  }
  @media (max-width: 800px) { .checks-grid { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 500px) { .checks-grid { grid-template-columns: 1fr; } }

  .check-item {
    display: flex; align-items: center; gap: 10px; padding: 10px 14px;
    border-radius: 10px; font-size: 13px;
  }
  .check-item.pass { background: #f0faf3; }
  .check-item.fail { background: #fff5f5; }
  .check-item.warn { background: #fffbf0; }

  .check-icon {
    width: 26px; height: 26px; border-radius: 50%; display: flex;
    align-items: center; justify-content: center; font-size: 13px;
    font-weight: 700; flex-shrink: 0;
  }
  .check-icon.pass { background: #34c759; color: #fff; }
  .check-icon.fail { background: #ff3b30; color: #fff; }
  .check-icon.warn { background: #ff9500; color: #fff; }

  .check-info { flex: 1; }
  .check-name { font-weight: 600; color: #1d1d1f; font-size: 13px; }
  .check-detail { color: #86868b; font-size: 12px; margin-top: 1px; }

  .drop-zone {
    border: 2px dashed #d2d2d7; border-radius: 12px; padding: 20px;
    text-align: center; color: #86868b; font-size: 14px; margin-top: 12px;
    transition: all 0.2s; display: none;
  }
  .drop-zone.active { border-color: #0071e3; background: #f0f4ff; color: #0071e3; }
</style>
</head>
<body>
<div class="container">
  <h1>Email <span>Checker Pro</span></h1>
  <p class="subtitle">7 verifications par email : Format, DNS/MX, Catch-all, SMTP, Gravatar, GitHub, Blacklist</p>

  <textarea id="emailInput" placeholder="Colle tes emails ici, ou importe un CSV...&#10;&#10;john@company.com&#10;jane@startup.io, founder@saas.com&#10;&#10;Tout format accepte : CSV, texte brut, un par ligne..."></textarea>

  <div class="drop-zone" id="dropZone">Glisse un fichier CSV ici</div>

  <div class="actions">
    <button class="btn-check" id="btnCheck" onclick="startCheck()">Verifier</button>
    <input type="file" id="csvFile" accept=".csv,.txt" onchange="handleCSV(this)">
    <label class="btn btn-csv" for="csvFile">Importer CSV</label>
    <button class="btn-clear" id="btnClear" onclick="clearAll()">Effacer</button>
    <button class="btn-export" id="btnExport" onclick="exportCSV()" disabled>Exporter CSV</button>
    <span class="count-info" id="countInfo"></span>
  </div>

  <div class="progress-bar" id="progressBar"><div class="fill" id="progressFill"></div></div>
  <div class="progress-text" id="progressText"></div>

  <div class="stats" id="stats">
    <div class="stat valid"><div class="num" id="nValid">0</div><div class="label">Valides</div></div>
    <div class="stat invalid"><div class="num" id="nInvalid">0</div><div class="label">Invalides</div></div>
    <div class="stat catchall"><div class="num" id="nCatchall">0</div><div class="label">Catch-all</div></div>
    <div class="stat unknown"><div class="num" id="nUnknown">0</div><div class="label">Inconnus</div></div>
  </div>

  <div class="results" id="results"></div>
</div>
<script>
var currentJobId = null;
var pollInterval = null;
var lastCount = 0;
var totalEmails = 0;
var isRunning = false;

function countEmails() {
  var m = document.getElementById('emailInput').value.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g);
  var n = m ? m.length : 0;
  document.getElementById('countInfo').textContent = n ? n + ' email' + (n > 1 ? 's' : '') + ' detecte' + (n > 1 ? 's' : '') : '';
  return n;
}

function startCheck() {
  var raw = document.getElementById('emailInput').value.trim();
  if (!raw) return;

  // Cancel any previous poll
  if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
  isRunning = true;
  document.getElementById('btnCheck').disabled = true;
  document.getElementById('btnCheck').textContent = 'Verification...';
  document.getElementById('btnExport').disabled = true;
  document.getElementById('results').innerHTML = '';
  document.getElementById('progressBar').style.display = 'block';
  document.getElementById('progressText').style.display = 'block';
  document.getElementById('stats').style.display = 'flex';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('progressText').textContent = 'Demarrage...';
  lastCount = 0;
  updateStats({valid: 0, invalid: 0, 'catch-all': 0, unknown: 0});

  fetch('/api/check', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({emails: raw})
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.error) {
      alert(data.error);
      resetBtn();
      return;
    }
    currentJobId = data.job_id;
    totalEmails = data.total;
    document.getElementById('countInfo').textContent = data.total + ' emails';
    pollInterval = setInterval(function() { pollStatus(); }, 800);
  })
  .catch(function(err) {
    alert('Erreur de connexion: ' + err.message);
    resetBtn();
  });
}

function resetBtn() {
  isRunning = false;
  document.getElementById('btnCheck').disabled = false;
  document.getElementById('btnCheck').textContent = 'Verifier';
}

function pollStatus() {
  if (!currentJobId) return;
  fetch('/api/status/' + currentJobId)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { clearInterval(pollInterval); resetBtn(); return; }

      var pct = totalEmails > 0 ? (data.checked / totalEmails * 100).toFixed(0) : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressText').textContent = data.checked + ' / ' + totalEmails + ' verifie' + (data.checked > 1 ? 's' : '') + ' (' + pct + '%)';

      var container = document.getElementById('results');
      for (var i = lastCount; i < data.results.length; i++) {
        container.appendChild(renderCard(data.results[i]));
      }
      lastCount = data.results.length;

      var c = {valid: 0, invalid: 0, 'catch-all': 0, unknown: 0};
      data.results.forEach(function(r) { c[r.status] = (c[r.status] || 0) + 1; });
      updateStats(c);

      if (data.done) {
        clearInterval(pollInterval);
        pollInterval = null;
        resetBtn();
        document.getElementById('btnExport').disabled = false;
        document.getElementById('progressFill').style.width = '100%';
        document.getElementById('progressText').textContent = 'Termine ! ' + totalEmails + ' email' + (totalEmails > 1 ? 's' : '') + ' verifie' + (totalEmails > 1 ? 's' : '');
      }
    })
    .catch(function() {});
}

function renderCard(r) {
  var card = document.createElement('div');
  card.className = 'result-card status-' + r.status;

  var top = document.createElement('div');
  top.className = 'result-top';

  var badge = document.createElement('span');
  badge.className = 'badge ' + r.status;
  var labels = {valid: 'VALIDE', 'catch-all': 'CATCH-ALL', invalid: 'INVALIDE', unknown: 'INCONNU'};
  badge.textContent = labels[r.status] || r.status.toUpperCase();

  var email = document.createElement('span');
  email.className = 'email-text';
  email.textContent = r.email;

  var sc = r.score || 0;
  var circle = document.createElement('div');
  circle.className = 'score-circle ' + (sc >= 65 ? 'high' : sc >= 35 ? 'mid' : 'low');
  circle.textContent = sc;

  top.appendChild(badge);
  top.appendChild(email);
  top.appendChild(circle);
  card.appendChild(top);

  if (r.checks && r.checks.length > 0) {
    var grid = document.createElement('div');
    grid.className = 'checks-grid';

    r.checks.forEach(function(ck) {
      var item = document.createElement('div');
      var cls = ck.pass === true ? 'pass' : ck.pass === false ? 'fail' : 'warn';
      item.className = 'check-item ' + cls;

      var icon = document.createElement('div');
      icon.className = 'check-icon ' + cls;
      icon.textContent = ck.pass === true ? '\u2713' : ck.pass === false ? '\u2717' : '!';

      var info = document.createElement('div');
      info.className = 'check-info';

      var name = document.createElement('div');
      name.className = 'check-name';
      name.textContent = ck.name;

      var detail = document.createElement('div');
      detail.className = 'check-detail';
      if (ck.url) {
        var link = document.createElement('a');
        link.href = ck.url;
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = ck.detail || '';
        link.style.cssText = 'color: #0071e3; text-decoration: none; font-weight: 500;';
        detail.appendChild(link);
      } else {
        detail.textContent = ck.detail || '';
      }

      info.appendChild(name);
      info.appendChild(detail);
      item.appendChild(icon);
      item.appendChild(info);
      grid.appendChild(item);
    });

    card.appendChild(grid);
  }

  return card;
}

function updateStats(c) {
  document.getElementById('nValid').textContent = c.valid || 0;
  document.getElementById('nInvalid').textContent = c.invalid || 0;
  document.getElementById('nCatchall').textContent = c['catch-all'] || 0;
  document.getElementById('nUnknown').textContent = c.unknown || 0;
}

function handleCSV(input) {
  var file = input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    var text = e.target.result;
    var emails = text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g);
    if (!emails || emails.length === 0) {
      alert('Aucun email trouve dans le fichier');
      return;
    }
    var unique = emails.filter(function(v, i, a) { return a.indexOf(v) === i; });
    var ta = document.getElementById('emailInput');
    if (ta.value.trim()) {
      ta.value = ta.value.trim() + '\n' + unique.join('\n');
    } else {
      ta.value = unique.join('\n');
    }
    countEmails();
  };
  reader.readAsText(file);
  input.value = '';
}

function clearAll() {
  if (isRunning) {
    if (!confirm('Verification en cours. Effacer quand meme ?')) return;
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    resetBtn();
  }
  document.getElementById('emailInput').value = '';
  document.getElementById('results').innerHTML = '';
  document.getElementById('progressBar').style.display = 'none';
  document.getElementById('progressText').style.display = 'none';
  document.getElementById('stats').style.display = 'none';
  document.getElementById('countInfo').textContent = '';
  document.getElementById('btnExport').disabled = true;
  currentJobId = null;
  lastCount = 0;
  totalEmails = 0;
}

function exportCSV() {
  if (currentJobId) window.location = '/api/export/' + currentJobId;
}

document.getElementById('emailInput').addEventListener('input', countEmails);

// Drag & drop CSV
var dropZone = document.getElementById('dropZone');
var ta = document.getElementById('emailInput');

ta.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.style.display = 'block'; dropZone.classList.add('active'); });
dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('active'); });
dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('active'); });
dropZone.addEventListener('drop', function(e) {
  e.preventDefault();
  dropZone.classList.remove('active');
  dropZone.style.display = 'none';
  var file = e.dataTransfer.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(ev) {
    var emails = ev.target.result.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g);
    if (!emails || emails.length === 0) { alert('Aucun email dans le fichier'); return; }
    var unique = emails.filter(function(v, i, a) { return a.indexOf(v) === i; });
    ta.value = ta.value.trim() ? ta.value.trim() + '\n' + unique.join('\n') : unique.join('\n');
    countEmails();
  };
  reader.readAsText(file);
});
document.addEventListener('dragover', function(e) { e.preventDefault(); });
document.addEventListener('drop', function(e) { e.preventDefault(); });
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  EMAIL CHECKER PRO")
    print("  http://localhost:5050")
    print(f"  GitHub: {'ON' if GH_TOKEN else 'OFF (set GH_TOKEN)'}")
    print("=" * 50 + "\n")
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
