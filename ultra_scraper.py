#!/usr/bin/env python3
"""
Ultra Email Scraper v2 — OSINT Hacker Edition
==============================================
100% GRATUIT. Techniques OSINT pour extraire des emails de startups.
Vérifie tous les emails via ton checker avant export.

Sources (10 techniques):
  1. GitHub commit search (author-email:@domain)
  2. GitHub org/user repo mining
  3. GitHub code search (@domain in source code)
  4. Website deep crawl (about/team/contact + sitemap + JS)
  5. YC directory → email pattern bruteforce
  6. Bing dorking (moins restrictif que Google)
  7. Wayback Machine (pages archivées)
  8. PGP keyservers (clés publiques = vrais emails)
  9. npm/PyPI packages (maintainer emails)
  10. theHarvester OSINT

Vérification finale:
  - Envoie tous les emails trouvés au checker Render pour les 9 checks

Usage:
  python3 ultra_scraper.py --domain firecrawl.dev
  python3 ultra_scraper.py --file domains_yc_ai.txt
  python3 ultra_scraper.py --file domains_yc_ai.txt --output results.csv
  python3 ultra_scraper.py --discover
"""
import csv, re, os, sys, time, argparse, hashlib, json, subprocess, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import quote_plus, quote

import requests
import dns.resolver

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
GH_TOKEN = os.environ.get("GH_TOKEN", "")

OUTPUT = "ultra_results.csv"
DONE_FILE = "ultra_done.txt"
WORKERS_SOURCES = 8
MAX_GH_REPOS = 8
MAX_GH_COMMITS = 40

write_lock = Lock()

# ── Sessions ─────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
})

GH_SESSION = requests.Session()
if GH_TOKEN:
    GH_SESSION.headers.update({
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "UltraScraper/2.0",
    })

# ── Filters ──────────────────────────────────────────────────
GENERIC_LOCALS = {
    "support", "hello", "info", "contact", "team", "press", "privacy", "legal",
    "security", "hr", "jobs", "careers", "noreply", "no-reply", "billing", "sales",
    "help", "admin", "founders", "founder", "server", "sandbox", "demo", "devops",
    "dev", "devs", "bot", "guest", "test", "test1", "test2", "local-admin",
    "feedback", "flow", "ai", "notify", "notifications", "alerts", "webhook",
    "ops", "infra", "engineering", "product", "design", "marketing", "finance",
    "accounting", "payroll", "invoice", "git", "github", "gitlab", "action",
    "root", "postmaster", "webmaster", "mailer-daemon", "abuse", "www",
    "email", "mail", "office", "reception", "general", "company", "service",
    "subscribe", "unsubscribe", "signup", "newsletter", "media", "partners",
    "example", "sentry", "user", "reply", "daemon", "system", "errors",
    "news", "blog", "docs", "app", "api", "status", "events", "community",
    "store", "shop", "cdn", "static", "staging", "prod", "config", "data",
    "void", "null", "undefined", "unknown", "anonymous", "bb", "xx", "yy",
    "dockerfile", "docker", "ci", "cd", "pipeline", "release", "deploy",
    "zen", "agent", "tech", "developer", "noreply", "no-reply",
    "enterprise", "marketplace", "growth", "project-feedback", "teste",
    "hellow", "email-matt", "pr", "ap", "rcs",
    # Ajouts : VC/investor-specific genericals
    "inquiries", "inquiry", "pitch", "pitches", "deck", "decks", "apply",
    "investor", "investors", "investment", "investments", "ir", "lp",
    "partner", "partnerships", "bd", "biz", "business", "exec", "executive",
    "research", "insights", "content", "editorial", "crypto", "opensource",
    "opensourceprogram", "oss", "community-team", "dev-rel",
    "karma", "accessibility", "a11y", "diversity", "dei", "people",
    "talent", "recruiting", "recruit", "recruitment", "culture",
    "events", "event", "conference", "summit", "webinar",
    "comms", "communication", "communications", "pr-team", "public-relations",
    "outreach", "grant", "grants", "submissions", "submission",
    "portfolio", "program", "programs", "accelerator", "incubator",
    "student", "students", "intern", "interns", "internship",
    "feedback-team", "audit", "compliance", "risk", "kyc", "aml",
    "verify", "verification", "security-team", "infosec", "bugbounty",
    "mailto", "share", "social", "instagram", "twitter", "linkedin",
    "tiktok", "youtube", "facebook", "discord", "slack", "telegram",
    "chat", "talk", "customer", "customers", "clients", "client",
    "public", "investorrelations", "shareholder", "shareholders",
    "education", "learn", "learning", "academy", "training", "trainings",
    "advisor", "advisors", "advisory", "board", "directors",
    "donations", "donation", "donate", "giving", "charity",
    "podcast", "podcasts", "video", "videos", "photo", "photos",
    "playbook", "playbooks", "brief", "briefs", "report", "reports",
}

# Pattern des locaux structurellement génériques (marketing / campagne / brand)
GENERIC_LOCAL_PATTERNS = re.compile(
    r"^("
    r"[a-z0-9]+-(ai|ml|eng|engineering|design|product|marketing|content|"
    r"comms|comm|press|pr|media|research|growth|sales|bd|biz|investor|lp|ir|"
    r"playbook|brief|report|newsletter|events?|summit|conference|podcast|"
    r"portfolio|apply|pitch|pitches?|submissions?|grants?|education|training|"
    r"recruiting|talent|hr|careers|jobs|diversity|dei|community|social|"
    r"program|accelerator|incubator|outreach|insights|editorial)s?"
    r"|"
    r"(ai|ml|crypto|web3|growth|gtm|marketing|media|pr|press|ops)-[a-z0-9]+"
    r")$",
    re.I,
)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def is_personal(email, domain):
    """Filtre: garde seulement les emails personnels du domaine."""
    if not email or "@" not in email:
        return False
    email = email.strip().lower()
    local, dom = email.split("@", 1)
    if dom != domain.lower() and dom != f"www.{domain.lower()}":
        return False
    if local in GENERIC_LOCALS:
        return False
    if GENERIC_LOCAL_PATTERNS.match(local):
        return False
    if local.isdigit() or len(local) < 2 or len(local) > 40:
        return False
    # Heuristique : locaux avec 3+ tirets = brand/campagne (ex: a16z-ai-playbook)
    if local.count("-") >= 2 or local.count(".") >= 3:
        return False
    if re.search(
        r"noreply|github|localdomain|bot|robot|auto|deploy|release|"
        r"action|ci[\-_]|jenkins|build|dependabot|renovate|snyk|"
        r"sentry|error|alert|monitor|cron|daemon|system|root|"
        r"test\d|staging|prod\-|\.png|\.jpg|\.svg|\.css|\.js",
        local,
    ):
        return False
    if not re.search(r"[a-zA-Z]", local):
        return False
    return True


def extract_emails(text, domain):
    found = EMAIL_RE.findall(text)
    return {e.lower() for e in found if is_personal(e, domain)}


# ══════════════════════════════════════════════════════════════
# GITHUB HELPERS
# ══════════════════════════════════════════════════════════════
def gh_get(url, params=None, accept=None):
    if not GH_TOKEN:
        return None
    headers = {}
    if accept:
        headers["Accept"] = accept
    for attempt in range(3):
        try:
            r = GH_SESSION.get(url, params=params, timeout=15, headers=headers)
            if r.status_code == 403:
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time(), 1)
                time.sleep(min(wait + 1, 90))
                continue
            if r.status_code in (404, 422):
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


def find_github_org(domain):
    base = domain.split(".")[0]
    candidates = [
        base + "hq", base + "HQ", base, base.replace("-", ""),
        base + "ai", base + "-ai", base + "inc", base + "io",
        base + "dev", base + "-dev", domain.replace(".", "-"),
    ]
    for c in candidates:
        data = gh_get(f"https://api.github.com/orgs/{c}")
        if data and "login" in data:
            return data["login"], "org"
    for c in candidates:
        data = gh_get(f"https://api.github.com/users/{c}")
        if data and data.get("type") == "Organization":
            return data["login"], "org"
        if data and data.get("type") == "User":
            repos = gh_get(f"https://api.github.com/users/{data['login']}/repos",
                          params={"per_page": 1})
            if repos:
                return data["login"], "user"
    return None, None


# ══════════════════════════════════════════════════════════════
# SOURCE 1: GitHub Commit Search (MEILLEURE SOURCE)
# ══════════════════════════════════════════════════════════════
def source_github_commit_search(domain):
    """Recherche directe dans tous les commits publics par @domain."""
    if not GH_TOKEN:
        return set(), "gh-commit-search"
    emails = set()
    data = gh_get(
        "https://api.github.com/search/commits",
        params={"q": f"author-email:@{domain}", "per_page": 100,
                "sort": "author-date", "order": "desc"},
        accept="application/vnd.github.cloak-preview+json",
    )
    if isinstance(data, dict):
        for item in data.get("items", []):
            try:
                author = item.get("commit", {}).get("author", {})
                email = author.get("email", "")
                name = author.get("name", "")
                if is_personal(email, domain):
                    emails.add((email.strip().lower(), name))
            except Exception:
                pass
    return emails, "gh-commit-search"


# ══════════════════════════════════════════════════════════════
# SOURCE 2: GitHub Org/User Repo Mining
# ══════════════════════════════════════════════════════════════
def source_github_repos(domain):
    """Mine les repos de l'org GitHub pour extraire les emails des commits."""
    if not GH_TOKEN:
        return set(), "gh-repos"
    emails = set()
    login, entity_type = find_github_org(domain)
    if not login:
        return emails, "gh-repos"

    url = (f"https://api.github.com/orgs/{login}/repos"
           if entity_type in ("org", "organization")
           else f"https://api.github.com/users/{login}/repos")

    repos = gh_get(url, params={"per_page": MAX_GH_REPOS, "sort": "pushed", "type": "public"})
    if not isinstance(repos, list):
        return emails, "gh-repos"

    for repo in repos[:MAX_GH_REPOS]:
        repo_name = repo.get("full_name", "")
        if not repo_name:
            continue
        commits = gh_get(
            f"https://api.github.com/repos/{repo_name}/commits",
            params={"per_page": MAX_GH_COMMITS},
        )
        if not isinstance(commits, list):
            continue
        for commit in commits:
            try:
                for person in [
                    commit.get("commit", {}).get("author", {}),
                    commit.get("commit", {}).get("committer", {}),
                ]:
                    email = person.get("email", "")
                    name = person.get("name", "")
                    if is_personal(email, domain):
                        emails.add((email.strip().lower(), name))
            except Exception:
                pass
    return emails, "gh-repos"


# ══════════════════════════════════════════════════════════════
# SOURCE 3: GitHub Code Search (emails dans le code source)
# ══════════════════════════════════════════════════════════════
def source_github_code(domain):
    """Cherche @domain dans le code source sur GitHub."""
    if not GH_TOKEN:
        return set(), "gh-code"
    emails = set()
    # Search in code for the email domain
    data = gh_get(
        "https://api.github.com/search/code",
        params={"q": f"@{domain} in:file", "per_page": 50},
    )
    if isinstance(data, dict):
        for item in data.get("items", [])[:30]:
            try:
                # Get file content
                raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                if raw_url:
                    r = SESSION.get(raw_url, timeout=8)
                    if r.status_code == 200:
                        found = extract_emails(r.text[:5000], domain)
                        for e in found:
                            emails.add((e, ""))
            except Exception:
                continue
    time.sleep(1)
    return emails, "gh-code"


# ══════════════════════════════════════════════════════════════
# SOURCE 4: Website Deep Crawl (pages + sitemap + JS files)
# ══════════════════════════════════════════════════════════════
TEAM_PATHS = [
    "/", "/about", "/about-us", "/team", "/our-team", "/people",
    "/company", "/contact", "/contact-us", "/founders", "/leadership",
    "/imprint", "/impressum", "/legal", "/privacy",  # German/EU sites
]


def source_website(domain):
    """Deep crawl du site web + sitemap + fichiers JS."""
    emails = set()

    # 1. Crawl main pages
    for base_url in [f"https://{domain}", f"https://www.{domain}"]:
        for path in TEAM_PATHS:
            try:
                r = SESSION.get(base_url + path, timeout=8, allow_redirects=True)
                if r.status_code == 200:
                    found = extract_emails(r.text, domain)
                    for e in found:
                        emails.add((e, ""))
                    # Extract JS files and check them too
                    js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)
                    for js in js_urls[:5]:
                        if js.startswith("/"):
                            js = base_url + js
                        elif not js.startswith("http"):
                            continue
                        try:
                            jr = SESSION.get(js, timeout=5)
                            if jr.status_code == 200:
                                found = extract_emails(jr.text[:10000], domain)
                                for e in found:
                                    emails.add((e, ""))
                        except Exception:
                            pass
            except Exception:
                continue
        if emails:
            break

    # 2. Try sitemap.xml
    for base_url in [f"https://{domain}", f"https://www.{domain}"]:
        try:
            r = SESSION.get(f"{base_url}/sitemap.xml", timeout=5)
            if r.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                team_urls = [u for u in urls if any(kw in u.lower() for kw in
                            ["team", "about", "people", "founder", "contact"])]
                for url in team_urls[:5]:
                    try:
                        pr = SESSION.get(url, timeout=8)
                        if pr.status_code == 200:
                            found = extract_emails(pr.text, domain)
                            for e in found:
                                emails.add((e, ""))
                    except Exception:
                        pass
        except Exception:
            pass

    return emails, "website"


# ══════════════════════════════════════════════════════════════
# SOURCE 5: YC Directory → Email Pattern Bruteforce
# ══════════════════════════════════════════════════════════════
YC_PARTNERS = {
    "Jared Friedman", "Michael Seibel", "Dalton Caldwell",
    "Gustaf Alstromer", "Aaron Epstein", "Brad Flora",
    "Diana Hu", "Harj Taggar", "Kevin Hale", "Kat Manalac",
    "Qasar Younis", "Tim Brady", "Adora Cheung",
    "Geoff Ralston", "Eric Migicovsky", "Garry Tan",
}


def scrape_yc_founders(domain):
    """Scrape YC directory pour trouver les noms des fondateurs."""
    base = domain.split(".")[0]
    slugs = [base, base.replace("-", ""), f"{base}-ai", f"{base}ai"]
    founders = []
    for slug in slugs:
        try:
            r = SESSION.get(f"https://www.ycombinator.com/companies/{slug}", timeout=10)
            if r.status_code == 200 and "Active Founders" in r.text:
                parts = r.text.split("Active Founders")
                if len(parts) > 1:
                    section = parts[1][:2000]
                    for cutoff in ["Latest News", "latestNews", "Hear from", "Jobs"]:
                        if cutoff in section:
                            section = section.split(cutoff)[0]
                            break
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(section, "html.parser")
                    for el in soup.find_all(["h3", "h4", "div", "span", "p"]):
                        txt = el.get_text(strip=True)
                        match = re.match(r"^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})$", txt)
                        if match and match.group(1) not in YC_PARTNERS:
                            founders.append(match.group(1))
                if founders:
                    break
        except Exception:
            continue
    return list(set(founders))


def generate_patterns(first, last, domain):
    f, l = first.lower().strip(), last.lower().strip()
    return [
        f"{f}@{domain}",
        f"{f}.{l}@{domain}",
        f"{f[0]}{l}@{domain}",
        f"{f}{l[0]}@{domain}",
        f"{f[0]}.{l}@{domain}",
        f"{f}_{l}@{domain}",
        f"{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{l}.{f}@{domain}",
    ]


def _verify_email_quick(email):
    """Vérification rapide via API gratuite (mailcheck.ai / disify)."""
    try:
        r = SESSION.get(f"https://api.mailcheck.ai/email/{email}", timeout=6)
        if r.status_code == 200:
            data = r.json()
            return data.get("status") == "valid" or data.get("mx", False)
    except Exception:
        pass
    try:
        r = SESSION.get(f"https://disify.com/api/email/{email}", timeout=6)
        if r.status_code == 200:
            data = r.json()
            return data.get("dns", False) and data.get("format", True) != False
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════
# CHECKER INTÉGRÉ — 7 checks comme ton app (100% gratuit)
# ══════════════════════════════════════════════════════════════
_mx_checker_cache = {}
_blacklist_cache = {}


def checker_format(email):
    """Check 1: Format email valide."""
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))


def checker_dns_mx(domain):
    """Check 2: DNS MX records."""
    if domain in _mx_checker_cache:
        return _mx_checker_cache[domain]
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx = sorted(records, key=lambda r: r.preference)
        host = str(mx[0].exchange).rstrip('.')
        _mx_checker_cache[domain] = host
        return host
    except Exception:
        _mx_checker_cache[domain] = None
        return None


def checker_api(email):
    """Check 3: API verification (mailcheck.ai + disify.com)."""
    result = {"deliverable": None, "disposable": False}
    try:
        r = SESSION.get(f"https://api.mailcheck.ai/email/{email}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            result["deliverable"] = not data.get("disposable", False) and data.get("mx", False)
            result["disposable"] = data.get("disposable", False)
            return result
    except Exception:
        pass
    try:
        r = SESSION.get(f"https://disify.com/api/email/{email}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            result["deliverable"] = data.get("dns", False) and data.get("format", True) != False
            result["disposable"] = data.get("disposable", False)
            return result
    except Exception:
        pass
    return result


def checker_gravatar(email):
    """Check 4: Gravatar profile."""
    try:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        r = SESSION.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def checker_github_commits(email):
    """Check 5: GitHub commits count."""
    if not GH_TOKEN:
        return None
    try:
        r = GH_SESSION.get(
            f"https://api.github.com/search/commits?q=author-email:{email}",
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("total_count", 0)
    except Exception:
        pass
    return None


def checker_github_profile(email):
    """Check 6: GitHub profile."""
    if not GH_TOKEN:
        return None
    try:
        r = GH_SESSION.get(
            f"https://api.github.com/search/users?q={email}+in:email",
            timeout=10,
        )
        if r.status_code == 200:
            items = r.json().get("items", [])
            if items:
                u = items[0]
                return {"login": u["login"], "url": u["html_url"]}
        # Fallback: find via commits
        r2 = GH_SESSION.get(
            f"https://api.github.com/search/commits?q=author-email:{email}",
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
            timeout=10,
        )
        if r2.status_code == 200:
            items2 = r2.json().get("items", [])
            if items2 and items2[0].get("author"):
                a = items2[0]["author"]
                return {"login": a["login"], "url": a["html_url"]}
    except Exception:
        pass
    return None


def checker_blacklist(domain):
    """Check 7: Blacklist DNSBL."""
    if domain in _blacklist_cache:
        return _blacklist_cache[domain]
    blacklists = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
    listed = []
    try:
        ip = dns.resolver.resolve(domain, 'A')[0].to_text()
        rev = '.'.join(reversed(ip.split('.')))
        for bl in blacklists:
            try:
                dns.resolver.resolve(f"{rev}.{bl}", 'A')
                listed.append(bl)
            except Exception:
                pass
    except Exception:
        pass
    _blacklist_cache[domain] = listed
    return listed


def run_full_check(email):
    """Exécute les 7 checks sur un email. Retourne score + détails."""
    domain = email.split("@")[1]
    score = 0
    checks = []

    # 1. Format
    fmt = checker_format(email)
    score += 10 if fmt else 0
    checks.append({"name": "Format", "pass": fmt})

    # 2. DNS/MX
    mx = checker_dns_mx(domain)
    score += 15 if mx else 0
    checks.append({"name": "DNS/MX", "pass": mx is not None, "detail": mx or "No MX"})

    # 3. API verification
    api = checker_api(email)
    if api["deliverable"]:
        score += 30
    if api["disposable"]:
        score -= 30
    checks.append({"name": "API Verify", "pass": api["deliverable"],
                    "detail": "disposable" if api["disposable"] else ""})

    # 4-7 en parallèle
    with ThreadPoolExecutor(max_workers=4) as pool:
        fut_grav = pool.submit(checker_gravatar, email)
        fut_gh = pool.submit(checker_github_commits, email)
        fut_ghp = pool.submit(checker_github_profile, email)
        fut_bl = pool.submit(checker_blacklist, domain)

        grav = fut_grav.result()
        gh = fut_gh.result()
        ghp = fut_ghp.result()
        bl = fut_bl.result()

    # 4. Gravatar
    score += 10 if grav else 0
    checks.append({"name": "Gravatar", "pass": grav})

    # 5. GitHub commits
    if gh is not None:
        score += 15 if gh > 0 else 0
        checks.append({"name": "GitHub Commits", "pass": gh > 0,
                        "detail": f"{gh} commits"})
    else:
        checks.append({"name": "GitHub Commits", "pass": None, "detail": "N/A"})

    # 6. GitHub profile
    if ghp:
        score += 10
        checks.append({"name": "GitHub Profil", "pass": True,
                        "detail": f"@{ghp['login']}", "url": ghp["url"]})
    else:
        checks.append({"name": "GitHub Profil", "pass": False})

    # 7. Blacklist
    clean = len(bl) == 0
    score += 10 if clean else -20
    checks.append({"name": "Blacklist", "pass": clean,
                    "detail": f"Listed: {', '.join(bl)}" if bl else "Clean"})

    # Status based on score
    if score >= 60:
        status = "verified"
    else:
        status = "invalid"

    return {
        "score": score,
        "status": status,
        "checks": checks,
        "github_profile": ghp,
    }


# ══════════════════════════════════════════════════════════════
# DÉTECTION DE POSTE (GitHub bio + heuristiques)
# ══════════════════════════════════════════════════════════════
ROLE_KEYWORDS = {
    "CEO": ["ceo", "chief executive"],
    "CTO": ["cto", "chief technology", "chief technical"],
    "COO": ["coo", "chief operating"],
    "CFO": ["cfo", "chief financial"],
    "CPO": ["cpo", "chief product"],
    "VP Engineering": ["vp eng", "vice president eng", "vp of eng"],
    "Co-Founder": ["co-founder", "cofounder", "co founder"],
    "Founder": ["founder", "fondateur", "founding"],
    "Head of Engineering": ["head of eng", "engineering lead", "eng lead"],
    "Head of Product": ["head of product", "product lead"],
    "Staff Engineer": ["staff eng", "staff software"],
    "Senior Engineer": ["senior eng", "senior software", "senior dev", "sr eng", "sr dev"],
    "Engineer": ["engineer", "developer", "dev ", "développeur", "swe "],
    "Designer": ["designer", "design lead", "head of design", "ux ", "ui "],
    "Data Scientist": ["data scien", "ml eng", "machine learning"],
    "Product Manager": ["product manager", "pm ", "product owner"],
    "DevRel": ["devrel", "developer relations", "developer advocate", "dev advocate"],
}


def detect_role_from_bio(bio):
    """Détecte le poste depuis une bio GitHub."""
    if not bio:
        return None
    bio_lower = bio.lower()
    # Check most specific roles first
    for role, keywords in ROLE_KEYWORDS.items():
        for kw in keywords:
            if kw in bio_lower:
                return role
    return None


def get_github_role(username):
    """Récupère le bio GitHub et détecte le poste."""
    if not GH_TOKEN or not username:
        return None
    try:
        data = gh_get(f"https://api.github.com/users/{username}")
        if data:
            bio = data.get("bio", "") or ""
            company = data.get("company", "") or ""
            full_text = f"{bio} {company}"
            role = detect_role_from_bio(full_text)
            return role
    except Exception:
        pass
    return None


def source_yc_patterns(domain):
    """Trouve les fondateurs YC puis bruteforce les patterns d'email."""
    emails = set()
    founders = scrape_yc_founders(domain)
    if not founders:
        return emails, "yc-bruteforce", []

    for name in founders:
        parts = name.split()
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        candidates = generate_patterns(first, last, domain)
        for candidate in candidates:
            valid = _verify_email_quick(candidate)
            if valid:
                emails.add((candidate, name))
                break
            time.sleep(0.3)

    return emails, "yc-bruteforce", founders


# ══════════════════════════════════════════════════════════════
# SOURCE 6: Bing Dorking (moins restrictif que Google)
# ══════════════════════════════════════════════════════════════
def source_bing(domain):
    """Bing est plus permissif que Google pour le dorking."""
    emails = set()
    queries = [
        f'"@{domain}"',
        f'"@{domain}" founder OR ceo OR cto',
        f'site:linkedin.com "@{domain}"',
        f'site:github.com "@{domain}"',
        f'site:twitter.com "@{domain}"',
    ]
    for query in queries:
        try:
            r = SESSION.get(
                "https://www.bing.com/search",
                params={"q": query, "count": 50},
                timeout=10,
            )
            if r.status_code == 200:
                found = extract_emails(r.text, domain)
                for e in found:
                    emails.add((e, ""))
            time.sleep(1)
        except Exception:
            continue
    return emails, "bing"


# ══════════════════════════════════════════════════════════════
# SOURCE 7: Wayback Machine (pages archivées)
# ══════════════════════════════════════════════════════════════
def source_wayback(domain):
    """Fouille les archives web pour trouver des emails sur d'anciennes pages."""
    emails = set()
    try:
        # Get archived URLs
        r = SESSION.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "original",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": 50,
            },
            timeout=15,
        )
        if r.status_code != 200:
            return emails, "wayback"

        urls = r.json()
        if not urls or len(urls) < 2:
            return emails, "wayback"

        # Filter for interesting pages
        keywords = ["about", "team", "contact", "people", "founder", "imprint"]
        interesting = []
        for row in urls[1:]:  # skip header
            url = row[0] if isinstance(row, list) else row
            if any(kw in url.lower() for kw in keywords):
                interesting.append(url)

        # Fetch cached versions
        for url in interesting[:8]:
            try:
                cached = SESSION.get(
                    f"https://web.archive.org/web/2024/{url}",
                    timeout=10,
                )
                if cached.status_code == 200:
                    found = extract_emails(cached.text, domain)
                    for e in found:
                        emails.add((e, ""))
            except Exception:
                continue
            time.sleep(0.5)

    except Exception:
        pass
    return emails, "wayback"


# ══════════════════════════════════════════════════════════════
# SOURCE 8: PGP Keyservers (vrais emails enregistrés)
# ══════════════════════════════════════════════════════════════
def source_pgp(domain):
    """Cherche les clés PGP publiques — emails vérifiés."""
    emails = set()
    keyservers = [
        f"https://keys.openpgp.org/vks/v1/by-email/{quote(f'@{domain}')}",
    ]
    # Also try HKP search
    try:
        r = SESSION.get(
            f"https://keys.openpgp.org/search",
            params={"q": domain},
            timeout=10,
        )
        if r.status_code == 200:
            found = extract_emails(r.text, domain)
            for e in found:
                emails.add((e, ""))
    except Exception:
        pass

    # Ubuntu keyserver
    try:
        r = SESSION.get(
            "https://keyserver.ubuntu.com/pks/lookup",
            params={"search": f"@{domain}", "op": "index"},
            timeout=10,
        )
        if r.status_code == 200:
            found = extract_emails(r.text, domain)
            for e in found:
                emails.add((e, ""))
    except Exception:
        pass

    return emails, "pgp"


# ══════════════════════════════════════════════════════════════
# SOURCE 9: npm / PyPI (package maintainer emails)
# ══════════════════════════════════════════════════════════════
def source_packages(domain):
    """Cherche les emails dans npm et PyPI packages."""
    emails = set()
    base = domain.split(".")[0]

    # npm — search for packages by org/company name
    try:
        r = SESSION.get(
            f"https://registry.npmjs.org/-/v1/search",
            params={"text": base, "size": 10},
            timeout=10,
        )
        if r.status_code == 200:
            for pkg in r.json().get("objects", []):
                info = pkg.get("package", {})
                # Check author email
                author = info.get("author", {}) or {}
                if isinstance(author, dict):
                    email = author.get("email", "")
                    name = author.get("name", "")
                    if email and is_personal(email, domain):
                        emails.add((email.lower(), name))
                # Check maintainers
                for m in info.get("maintainers", []):
                    email = m.get("email", "")
                    name = m.get("username", "")
                    if email and is_personal(email, domain):
                        emails.add((email.lower(), name))
    except Exception:
        pass

    # PyPI — search for packages
    try:
        r = SESSION.get(f"https://pypi.org/simple/", timeout=5)
        # PyPI simple API is just a list — instead search specific packages
        for pkg_name in [base, base.replace("-", "_"), base.replace("_", "-"),
                         f"{base}-sdk", f"{base}-python", f"{base}-client"]:
            try:
                r = SESSION.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5)
                if r.status_code == 200:
                    data = r.json().get("info", {})
                    email = data.get("author_email", "")
                    name = data.get("author", "")
                    if email:
                        # Can be comma-separated
                        for e in email.split(","):
                            e = e.strip()
                            if is_personal(e, domain):
                                emails.add((e.lower(), name))
            except Exception:
                continue
    except Exception:
        pass

    return emails, "packages"


# ══════════════════════════════════════════════════════════════
# SOURCE 10: theHarvester OSINT
# ══════════════════════════════════════════════════════════════
def source_theharvester(domain):
    """OSINT tool — github-code, hackertarget, rapiddns."""
    emails = set()
    sources = ["github-code", "hackertarget", "rapiddns"]
    for source in sources:
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-b", source, "-l", "200"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            found = extract_emails(output, domain)
            for e in found:
                emails.add((e, ""))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return emails, "harvester"



# ══════════════════════════════════════════════════════════════
# MAIN HARVESTER — 10 sources en parallèle
# ══════════════════════════════════════════════════════════════
def harvest_domain(domain, verbose=False):
    """Run les 10 sources en parallèle, vérifie via checker."""
    all_emails = {}  # email -> {name, sources}
    founders_found = []
    source_counts = {}

    if verbose:
        print(f"\n  🔍 {domain}")

    with ThreadPoolExecutor(max_workers=WORKERS_SOURCES) as pool:
        futures = {
            pool.submit(source_github_commit_search, domain): "gh-commit-search",
            pool.submit(source_github_repos, domain): "gh-repos",
            pool.submit(source_github_code, domain): "gh-code",
            pool.submit(source_website, domain): "website",
            pool.submit(source_bing, domain): "bing",
            pool.submit(source_wayback, domain): "wayback",
            pool.submit(source_pgp, domain): "pgp",
            pool.submit(source_packages, domain): "packages",
            pool.submit(source_theharvester, domain): "harvester",
        }
        fut_yc = pool.submit(source_yc_patterns, domain)

        for future in as_completed(futures):
            source_name = futures[future]
            try:
                result = future.result(timeout=60)
                emails_set, src = result[0], result[1]
                source_counts[src] = len(emails_set)
                for item in emails_set:
                    email = item[0] if isinstance(item, tuple) else item
                    name = item[1] if isinstance(item, tuple) and len(item) > 1 else ""
                    if email not in all_emails:
                        all_emails[email] = {"name": name, "sources": [src]}
                    else:
                        all_emails[email]["sources"].append(src)
                        if name and not all_emails[email]["name"]:
                            all_emails[email]["name"] = name
            except Exception as e:
                source_counts[source_name] = 0
                if verbose:
                    print(f"    ⚠️  {source_name}: {e}")

        try:
            yc_result = fut_yc.result(timeout=60)
            yc_emails, yc_src, founders_found = yc_result
            source_counts[yc_src] = len(yc_emails)
            for item in yc_emails:
                email = item[0] if isinstance(item, tuple) else item
                name = item[1] if isinstance(item, tuple) and len(item) > 1 else ""
                if email not in all_emails:
                    all_emails[email] = {"name": name, "sources": [yc_src]}
                else:
                    all_emails[email]["sources"].append(yc_src)
                    if name and not all_emails[email]["name"]:
                        all_emails[email]["name"] = name
        except Exception as e:
            source_counts["yc-bruteforce"] = 0

    # ══ CHECKER INTÉGRÉ — chaque email passe les 7 checks ══
    if verbose and all_emails:
        print(f"    🔎 Vérification de {len(all_emails)} emails (7 checks)...")

    checker_results = {}
    emails_to_check = list(all_emails.keys())

    # Run checker on 3 emails at a time (pour pas exploser les rate limits)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {pool.submit(run_full_check, e): e for e in emails_to_check}
        for fut in as_completed(futs):
            email = futs[fut]
            try:
                checker_results[email] = fut.result(timeout=30)
            except Exception:
                checker_results[email] = {"score": 0, "status": "error", "checks": []}

    # ── Build results — only keep verified/likely ──
    results = []
    for email, info in all_emails.items():
        check = checker_results.get(email, {})
        status = check.get("status", "unknown")
        score = check.get("score", 0)

        # Skip tout ce qui est sous 60 — que du solide
        if status == "invalid" or score < 60:
            continue

        name = info["name"]
        if not name:
            local = email.split("@")[0]
            parts = re.split(r"[._\-]", local)
            name_parts = [p.capitalize() for p in parts if len(p) > 1 and not p.isdigit()]
            if name_parts:
                name = " ".join(name_parts)

        # GitHub profile from checker
        ghp = check.get("github_profile")
        github_url = ghp["url"] if ghp else ""
        gh_login = ghp["login"] if ghp else ""

        # Detect role — GitHub bio + YC founders crossref
        poste = ""
        if gh_login:
            poste = get_github_role(gh_login) or ""
        # If name matches a YC founder → mark as Founder
        if not poste and founders_found:
            for fn in founders_found:
                if name and (fn.lower() in name.lower() or name.lower() in fn.lower()):
                    poste = "Founder"
                    break
        if not poste:
            poste = "Team"

        # LinkedIn search URL
        local = email.split("@")[0]
        company = domain.split(".")[0]
        name_parts = re.split(r"[._\-]", local)
        name_clean = [p.capitalize() for p in name_parts if len(p) > 1 and not p.isdigit()]
        linkedin_url = ""
        if name_clean:
            q = "+".join(name_clean + [company])
            linkedin_url = f"https://www.linkedin.com/search/results/people/?keywords={q}"

        results.append({
            "company": domain.split(".")[0].capitalize(),
            "domain": domain,
            "email": email,
            "name": name,
            "poste": poste,
            "sources": "+".join(sorted(set(info["sources"]))),
            "status": status,
            "score": score,
            "github": github_url,
            "linkedin": linkedin_url,
            "founders": ", ".join(founders_found) if founders_found else "",
        })

    # Sort: verified first, then by source count
    results.sort(key=lambda r: (
        0 if r["status"] == "verified" else 1,
        -len(r["sources"].split("+")),
    ))

    if verbose:
        src_str = " | ".join(f"{k}:{v}" for k, v in source_counts.items() if v > 0)
        found_str = f" founders={','.join(founders_found)}" if founders_found else ""
        if results:
            print(f"    ✅ {len(results)} emails ({src_str}){found_str}")
            for r in results:
                print(f"       {r['email']:35s} [{r['status']:8s}] {r['name']} ({r['poste']})")
        else:
            print(f"    ❌ Aucun email ({src_str})")

    return results, source_counts, founders_found


# ══════════════════════════════════════════════════════════════
# AUTO-DISCOVER: startup domains from awesome lists
# ══════════════════════════════════════════════════════════════
AWESOME_REPOS = [
    "e2b-dev/awesome-ai-agents",
    "kyrolabs/awesome-agents",
    "slavakurilyak/awesome-ai-agents",
    "Jenqyang/Awesome-AI-Agents",
]

SKIP_DOMAINS = {
    "github.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "discord.gg", "discord.com", "arxiv.org", "medium.com", "notion.so",
    "huggingface.co", "openai.com", "anthropic.com", "google.com",
    "reddit.com", "producthunt.com", "npmjs.com", "pypi.org",
    "vercel.app", "netlify.app", "substack.com", "wikipedia.org",
    "microsoft.com", "apple.com", "amazon.com", "aws.amazon.com",
}

URL_RE = re.compile(r"https?://(?:www\.)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)")


def discover_domains():
    """Auto-discover startup domains from awesome lists."""
    domains = set()
    if not GH_TOKEN:
        print("  ⚠️  GH_TOKEN requis pour --discover")
        return []

    print("  🔎 Découverte de startups depuis GitHub awesome lists...")
    for repo in AWESOME_REPOS:
        try:
            r = GH_SESSION.get(f"https://api.github.com/repos/{repo}/readme", timeout=12)
            if r.status_code != 200:
                continue
            content = base64.b64decode(r.json()["content"]).decode("utf-8", errors="ignore")
            urls = URL_RE.findall(content)
            for d in urls:
                d = d.lower().rstrip(".")
                if not any(skip in d for skip in SKIP_DOMAINS) and len(d.split(".")[0]) > 2:
                    domains.add(d)
            print(f"    [{repo}] → {len(domains)} domaines uniques")
            time.sleep(0.5)
        except Exception as e:
            print(f"    [{repo}] erreur: {e}")

    print(f"  📋 Total découvert: {len(domains)} domaines")
    return sorted(domains)


# ══════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════
def load_done():
    if os.path.exists(DONE_FILE):
        with open(DONE_FILE) as f:
            return {l.strip() for l in f if l.strip()}
    return set()


def save_done(domain):
    with open(DONE_FILE, "a") as f:
        f.write(domain + "\n")


def main():
    parser = argparse.ArgumentParser(description="Ultra Email Scraper v2 — OSINT Hacker Edition")
    parser.add_argument("--domain", help="Scrape un seul domaine")
    parser.add_argument("--file", help="Fichier de domaines (un par ligne)")
    parser.add_argument("--discover", action="store_true", help="Auto-découvrir des startups")
    parser.add_argument("--output", default=OUTPUT)
    parser.add_argument("--reset", action="store_true", help="Reset la liste done")
    args = parser.parse_args()

    if args.reset and os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)

    FIELDNAMES = ["company", "domain", "email", "name", "poste", "sources", "status", "score", "github", "linkedin", "founders"]

    # ── Single domain ──
    if args.domain:
        print(f"\n{'='*60}")
        print(f"  ULTRA SCRAPER v2 — OSINT HACKER EDITION")
        print(f"  Target: {args.domain}")
        print(f"{'='*60}")
        print(f"  GitHub token : {'SET' if GH_TOKEN else 'NOT SET ⚠️'}")
        print(f"  Checker      : 7 checks intégrés (Format/DNS/API/Gravatar/GitHub/Blacklist)")
        print(f"  Sources      : 10 techniques OSINT")
        print(f"{'='*60}")

        results, sources, founders = harvest_domain(args.domain, verbose=True)

        if results:
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
                writer.writeheader()
                for r in results:
                    writer.writerow(r)
            print(f"\n  💾 {len(results)} emails → {args.output}")
        return

    # ── Batch mode ──
    domains = []
    if args.discover:
        domains = discover_domains()
    elif args.file:
        with open(args.file) as f:
            domains = [l.strip() for l in f if l.strip()]
    else:
        print("Usage: --domain X | --file domains.txt | --discover")
        return

    done = load_done()
    todo = [d for d in domains if d not in done]

    print(f"\n{'='*60}")
    print(f"  ULTRA SCRAPER v2 — OSINT HACKER EDITION")
    print(f"{'='*60}")
    print(f"  Domaines      : {len(domains)} total, {len(todo)} restants")
    print(f"  GitHub token  : {'SET' if GH_TOKEN else 'NOT SET ⚠️'}")
    print(f"  Checker       : 7 checks intégrés")
    print(f"  Sources       : 10 techniques OSINT")
    print(f"  Output        : {args.output}")
    print(f"{'='*60}\n")

    if not todo:
        print("  Rien à faire !")
        return

    found_total = 0
    processed = 0
    domains_ok = 0

    file_exists = os.path.exists(args.output) and os.path.getsize(args.output) > 10
    mode = "a" if file_exists else "w"

    with open(args.output, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()

        for domain in todo:
            try:
                results, sources, founders = harvest_domain(domain, verbose=False)
            except Exception as e:
                print(f"  ❌ {domain}: {e}")
                save_done(domain)
                continue

            processed += 1
            save_done(domain)

            if results:
                with write_lock:
                    for r in results:
                        writer.writerow(r)
                    fh.flush()
                found_total += len(results)
                domains_ok += 1
                src_str = " | ".join(f"{k}:{v}" for k, v in sources.items() if v > 0)
                founders_str = f" [{','.join(founders)}]" if founders else ""
                print(f"[{processed:>4}/{len(todo)}] ✅ {domain:30s} +{len(results):>3} ({src_str}){founders_str}")
            else:
                print(f"[{processed:>4}/{len(todo)}] ❌ {domain}")

    print(f"\n{'='*60}")
    print(f"  TERMINÉ")
    print(f"  Domaines scrapés    : {processed}")
    print(f"  Domaines avec email : {domains_ok}")
    print(f"  Total emails        : {found_total}")
    print(f"  Fichier             : {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
