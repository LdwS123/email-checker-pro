#!/usr/bin/env python3
"""
Ultra Email Scraper v2 — OSINT Hacker Edition
==============================================
100% GRATUIT. Techniques OSINT pour extraire des emails de startups.
Vérifie tous les emails via ton checker avant export.

Sources (18 techniques) + pattern inference:
  1.  GitHub commit search     10. crt.sh (subdomain enum)
  2.  GitHub org/user repos    11. HackerNews (Algolia)
  3.  GitHub code search       12. Reddit (posts + user bios)
  4.  Website deep crawl       13. StackExchange (about_me)
  5.  YC directory brute       14. Mastodon (federated)
  6.  Bing dorking              15. ProductHunt (maker pages)
  7.  Wayback Machine           16. WHOIS (registrant)
  8.  PGP keyservers            17. SEC EDGAR (US filings)
  9.  npm/PyPI maintainers      18. theHarvester OSINT

Pattern inference:
  - Parses team pages for "Firstname Lastname" tokens (BeautifulSoup)
  - Infers email pattern from already-verified (email, name) pairs
  - Generates + verifies candidates via mailcheck.ai / disify
  - Biggest yield multiplier: 1 known email + 10 names → 5-10 new emails

Role extraction:
  - Scans text within 140 chars of every email for role keywords
    (CEO, Founder, Partner, Head of, ...) and stamps the role in the CSV.

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
WORKERS_SOURCES = 14
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
    # Token-split: if ANY token (split on . - _ +) is a generic term, reject.
    # Catches "santamonica-info", "pitch-deck", "investor.relations" etc.
    tokens = re.split(r"[.\-_+]", local)
    if len(tokens) >= 2:
        for t in tokens:
            if t in GENERIC_LOCALS:
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
    "/staff", "/directors", "/leadership", "/partners",
    "/company", "/who-we-are", "/who", "/meet-the-team",
    "/contact", "/contact-us", "/connect", "/hello",
    "/founders", "/investors", "/portfolio",
    "/press", "/media", "/newsroom", "/news",
    "/careers", "/jobs", "/join-us", "/join",
    "/blog", "/blog/authors", "/authors",
    "/imprint", "/impressum", "/legal", "/privacy", "/mentions-legales",
]

# Titles we consider valid founder/employee names on team pages.
_NAME_RE = re.compile(
    r"\b([A-Z][a-zàâäéèêëîïôöùûüç]{1,19}(?:\s+(?:de|van|von|der|la|le|del|da|di)\s+[A-Z][a-zàâäéèêëîïôöùûüç]{1,19})?"
    r"(?:\s+[A-Z][a-zàâäéèêëîïôöùûüç]{1,19}){1,2})\b"
)

ROLE_RE = re.compile(
    r"\b("
    r"ceo|cto|cfo|coo|cmo|cpo|cso|vp|svp|evp|president|founder|co[\-\s]?founder|"
    r"chief|partner|gp|general\s+partner|managing\s+director|director|"
    r"head\s+of|lead|principal|engineer|developer|researcher|scientist|"
    r"designer|marketer|pr|press|recruiter|talent|hr|people|"
    r"investor|analyst|associate|operating\s+partner|advisor|board|trustee|"
    r"editor|journalist|author|writer|reporter|correspondent"
    r")\b",
    re.IGNORECASE,
)


def _extract_names_from_html(html):
    """Extract plausible 'Firstname Lastname' tokens from team-style pages.

    Focuses on headings/cards: <h1-h4>, <strong>, <b>, common card divs.
    Returns a list preserving order, deduplicated.
    """
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    seen = set()
    names = []
    candidates = soup.find_all(["h1", "h2", "h3", "h4", "h5",
                                "strong", "b", "figcaption"])
    for el in candidates:
        txt = (el.get_text(" ", strip=True) or "")[:80]
        m = _NAME_RE.search(txt)
        if not m:
            continue
        name = m.group(1).strip()
        # Filter obvious non-names
        if name.lower() in {"read more", "learn more", "our team", "about us",
                            "case study", "press release", "privacy policy"}:
            continue
        # Require at least two capitalized tokens
        if len(name.split()) < 2:
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
        if len(names) >= 60:
            break
    return names


def source_website(domain):
    """Deep crawl: TEAM_PATHS × {apex, www} + sitemap(s) + robots.txt Sitemap.

    Extracts both emails AND candidate person names (for pattern inference).
    Returns (emails_with_names, "website", scraped_names).
    """
    emails = set()
    email_role = {}  # email -> role (first non-empty wins)
    scraped_names = []
    visited = set()

    def _ingest(html):
        for e in extract_emails(html, domain):
            emails.add((e, ""))
            if e not in email_role:
                role = extract_role_near_email(html, e)
                if role:
                    email_role[e] = role
        for n in _extract_names_from_html(html):
            if n not in scraped_names:
                scraped_names.append(n)

    # 1. Direct TEAM_PATHS on both apex + www
    for base_url in (f"https://{domain}", f"https://www.{domain}"):
        for path in TEAM_PATHS:
            url = base_url + path
            if url in visited:
                continue
            visited.add(url)
            try:
                r = SESSION.get(url, timeout=8, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200 or len(r.text) < 100:
                continue
            _ingest(r.text)
            # JS files (obfuscated team data sometimes lives in JSON bundles)
            for js in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)[:5]:
                if js.startswith("/"):
                    js = base_url + js
                elif not js.startswith("http"):
                    continue
                try:
                    jr = SESSION.get(js, timeout=5)
                    if jr.status_code == 200:
                        for e in extract_emails(jr.text[:30000], domain):
                            emails.add((e, ""))
                except Exception:
                    pass
        if emails or scraped_names:
            # Reasonably covered — skip www duplicate
            break

    # 2. Sitemap(s) — resolve via robots.txt + standard paths
    sitemap_urls = []
    for base_url in (f"https://{domain}", f"https://www.{domain}"):
        try:
            rr = SESSION.get(f"{base_url}/robots.txt", timeout=5)
            if rr.status_code == 200:
                for line in rr.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_urls.append(line.split(":", 1)[1].strip())
        except Exception:
            pass
        for p in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml"):
            sitemap_urls.append(base_url + p)

    keyword_re = re.compile(r"(team|about|people|founder|leadership|staff|"
                            r"partner|investor|contact|press|author|blog)",
                            re.IGNORECASE)

    sitemap_fetched = 0
    picked_urls = set()
    for sm_url in sitemap_urls[:6]:
        if sitemap_fetched >= 4:
            break
        try:
            r = SESSION.get(sm_url, timeout=6)
            if r.status_code != 200:
                continue
            sitemap_fetched += 1
            # Handle sitemap indexes too
            inner = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)
            for u in inner:
                if u.endswith(".xml") and sitemap_fetched < 6:
                    try:
                        ri = SESSION.get(u, timeout=6)
                        if ri.status_code == 200:
                            sitemap_fetched += 1
                            for u2 in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", ri.text):
                                if keyword_re.search(u2):
                                    picked_urls.add(u2)
                    except Exception:
                        pass
                elif keyword_re.search(u):
                    picked_urls.add(u)
        except Exception:
            pass

    for u in list(picked_urls)[:10]:
        if u in visited:
            continue
        visited.add(u)
        try:
            pr = SESSION.get(u, timeout=8)
            if pr.status_code == 200:
                _ingest(pr.text)
        except Exception:
            pass

    return emails, "website", scraped_names, email_role


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
# SOURCE 11: Certificate Transparency (crt.sh) — subdomain enum
# ══════════════════════════════════════════════════════════════
def source_crtsh(domain):
    """Enumerate subdomains via crt.sh (Certificate Transparency logs),
    then scrape the top N subdomains for personal emails of the root
    domain. Free, no auth, covers api/careers/staff/etc. subs."""
    emails = set()
    try:
        r = SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=20,
        )
        if r.status_code != 200:
            return emails, "crtsh"
        # crt.sh occasionally returns HTML when overloaded — guard.
        try:
            data = r.json()
        except Exception:
            return emails, "crtsh"
    except Exception:
        return emails, "crtsh"

    subs = set()
    for entry in data or []:
        name = (entry.get("name_value") or "").lower()
        for line in name.split("\n"):
            line = line.strip().lstrip("*.")
            if line.endswith(f".{domain}") and line != domain:
                # Skip deep wildcards (foo.bar.baz.domain) — mostly noise
                if line.count(".") <= domain.count(".") + 2:
                    subs.add(line)

    # Cap to keep latency bounded (crt.sh can return hundreds)
    TOP_N = 8
    priority_prefixes = ("www", "blog", "about", "team", "careers", "jobs",
                         "staff", "people", "press", "contact", "hello")
    ranked = sorted(subs, key=lambda s: (
        0 if s.split(".")[0] in priority_prefixes else 1,
        len(s),
    ))[:TOP_N]

    for sub in ranked:
        for scheme in ("https", "http"):
            try:
                rr = SESSION.get(f"{scheme}://{sub}", timeout=6,
                                 allow_redirects=True)
                if rr.status_code == 200:
                    for e in extract_emails(rr.text, domain):
                        emails.add((e, ""))
                    break
            except Exception:
                continue

    return emails, "crtsh"


# ══════════════════════════════════════════════════════════════
# SOURCE 12: HackerNews — bios + posts via Algolia HN API
# ══════════════════════════════════════════════════════════════
def source_hackernews(domain):
    """Search HackerNews for mentions of the domain, collect authors,
    then fetch each author's HN profile — `about` fields frequently
    contain personal emails ("contact me: x@y.com"). Free, no auth."""
    emails = set()
    authors = set()

    # Step 1 — search stories/comments referencing the domain
    try:
        r = SESSION.get(
            "https://hn.algolia.com/api/v1/search",
            params={"query": domain, "hitsPerPage": 50,
                    "tags": "(story,comment)"},
            timeout=10,
        )
        if r.status_code != 200:
            return emails, "hackernews"
        for hit in r.json().get("hits", []) or []:
            author = hit.get("author")
            if author:
                authors.add(author)
            # Opportunistically scan story_text / comment_text
            for field in ("story_text", "comment_text", "url"):
                text = hit.get(field) or ""
                for e in extract_emails(text, domain):
                    emails.add((e, author or ""))
    except Exception:
        return emails, "hackernews"

    # Step 2 — fetch each author's profile, scrape the bio
    AUTHOR_CAP = 20
    for author in list(authors)[:AUTHOR_CAP]:
        try:
            rr = SESSION.get(
                f"https://hn.algolia.com/api/v1/users/{author}",
                timeout=6,
            )
            if rr.status_code != 200:
                continue
            about = (rr.json() or {}).get("about") or ""
            if not about:
                continue
            for e in extract_emails(about, domain):
                emails.add((e, author))
        except Exception:
            continue

    return emails, "hackernews"


# ══════════════════════════════════════════════════════════════
# SOURCE 13: Reddit — posts/comments referencing the domain
# ══════════════════════════════════════════════════════════════
def source_reddit(domain):
    """Search public Reddit JSON endpoint for posts mentioning the domain,
    then scan selftext/title/user profiles for personal emails. Free, no auth."""
    emails = set()
    try:
        r = SESSION.get(
            "https://www.reddit.com/search.json",
            params={"q": domain, "limit": 50, "sort": "relevance"},
            headers={"User-Agent": "ultra-scraper/2.0 (contact)"},
            timeout=10,
        )
        if r.status_code != 200:
            return emails, "reddit"
        posts = (r.json().get("data") or {}).get("children", []) or []
    except Exception:
        return emails, "reddit"

    authors = set()
    for p in posts:
        data = p.get("data", {}) or {}
        for field in ("selftext", "title", "url"):
            text = data.get(field) or ""
            for e in extract_emails(text, domain):
                emails.add((e, data.get("author") or ""))
        author = data.get("author")
        if author and author != "[deleted]":
            authors.add(author)

    for author in list(authors)[:10]:
        try:
            rr = SESSION.get(
                f"https://www.reddit.com/user/{author}/about.json",
                headers={"User-Agent": "ultra-scraper/2.0"},
                timeout=6,
            )
            if rr.status_code != 200:
                continue
            sub = (rr.json().get("data") or {}).get("subreddit") or {}
            about = sub.get("public_description", "") or ""
            for e in extract_emails(about, domain):
                emails.add((e, author))
        except Exception:
            continue

    return emails, "reddit"


# ══════════════════════════════════════════════════════════════
# SOURCE 14: StackExchange — user bios across SO network
# ══════════════════════════════════════════════════════════════
def source_stackexchange(domain):
    """Search StackOverflow for users whose 'about_me' mentions the domain.
    about_me frequently contains contact emails. Free API, ~300 req/day anon."""
    emails = set()
    try:
        r = SESSION.get(
            "https://api.stackexchange.com/2.3/users",
            params={"site": "stackoverflow", "inname": domain.split(".")[0],
                    "pagesize": 30, "order": "desc", "sort": "reputation",
                    "filter": "!9Z(-wzftf"},
            timeout=10,
        )
        if r.status_code != 200:
            return emails, "stackexchange"
        for u in r.json().get("items", []) or []:
            about = u.get("about_me") or ""
            display = u.get("display_name") or ""
            if domain.lower() in (about + " " + (u.get("website_url") or "")).lower():
                for e in extract_emails(about, domain):
                    emails.add((e, display))
    except Exception:
        return emails, "stackexchange"
    return emails, "stackexchange"


# ══════════════════════════════════════════════════════════════
# SOURCE 15: Mastodon — federated public search
# ══════════════════════════════════════════════════════════════
def source_mastodon(domain):
    """Search Mastodon statuses + account bios mentioning the domain.
    Instance mastodon.social federates the network. Free, no auth."""
    emails = set()
    for query in (domain, f"@{domain.split('.')[0]}"):
        try:
            r = SESSION.get(
                "https://mastodon.social/api/v2/search",
                params={"q": query, "type": "statuses", "resolve": "false",
                        "limit": 20},
                timeout=10,
            )
            if r.status_code != 200:
                continue
            for s in r.json().get("statuses", []) or []:
                content = s.get("content") or ""
                acc = s.get("account") or {}
                display = acc.get("display_name") or ""
                for e in extract_emails(content, domain):
                    emails.add((e, display))
                note = acc.get("note") or ""
                for e in extract_emails(note, domain):
                    emails.add((e, display))
        except Exception:
            continue
    return emails, "mastodon"


# ══════════════════════════════════════════════════════════════
# SOURCE 16: ProductHunt — product/maker HTML pages
# ══════════════════════════════════════════════════════════════
def source_producthunt(domain):
    """Scrape ProductHunt product + maker pages. Free, no auth (HTML scrape)."""
    emails = set()
    base = domain.split(".")[0]
    slugs = [base, base.replace("-", ""), f"{base}-app", f"{base}-ai"]
    for slug in slugs[:4]:
        try:
            r = SESSION.get(
                f"https://www.producthunt.com/products/{slug}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=8,
            )
            if r.status_code == 200 and len(r.text) > 500:
                for e in extract_emails(r.text, domain):
                    emails.add((e, ""))
        except Exception:
            continue
    return emails, "producthunt"


# ══════════════════════════════════════════════════════════════
# SOURCE 17: WHOIS — domain registrant
# ══════════════════════════════════════════════════════════════
def source_whois(domain):
    """Registrant email via `whois` CLI. Most are GDPR-redacted but
    non-EU / small domains often still expose owner contact. Free."""
    emails = set()
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=12,
        )
        output = result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return emails, "whois"
    for e in extract_emails(output, domain):
        emails.add((e, ""))
    return emails, "whois"


# ══════════════════════════════════════════════════════════════
# SOURCE 18: SEC EDGAR — US filings full-text search
# ══════════════════════════════════════════════════════════════
def source_sec_edgar(domain):
    """SEC EDGAR full-text search. US startups that filed Form D / S-1 /
    10-K sometimes list a contact email in the filing. Free, no auth."""
    emails = set()
    try:
        r = SESSION.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": f'"{domain}"', "forms": "S-1,D,10-K,8-K"},
            headers={"User-Agent": "ultra-scraper research@example.com"},
            timeout=12,
        )
        if r.status_code != 200:
            return emails, "sec"
        hits = (r.json().get("hits") or {}).get("hits", []) or []
    except Exception:
        return emails, "sec"

    for h in hits[:3]:
        src = h.get("_source") or {}
        adsh = (src.get("adsh") or "").replace("-", "")
        cik = (src.get("ciks") or [None])[0]
        if not adsh or not cik:
            continue
        url = f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{adsh}"
        try:
            rr = SESSION.get(url, timeout=8, headers={
                "User-Agent": "ultra-scraper research@example.com"})
            if rr.status_code == 200:
                for e in extract_emails(rr.text[:50000], domain):
                    emails.add((e, ""))
        except Exception:
            continue
    return emails, "sec"


# ══════════════════════════════════════════════════════════════
# PATTERN INFERENCE — biggest yield multiplier
# ══════════════════════════════════════════════════════════════
def _ascii_slug(s):
    """Normalize name to lowercase ASCII for email-local comparison."""
    s = (s or "").lower().strip()
    table = str.maketrans({
        "à": "a", "â": "a", "ä": "a", "á": "a", "ã": "a",
        "é": "e", "è": "e", "ê": "e", "ë": "e",
        "î": "i", "ï": "i", "í": "i",
        "ô": "o", "ö": "o", "ó": "o", "ò": "o", "õ": "o",
        "ù": "u", "û": "u", "ü": "u", "ú": "u",
        "ç": "c", "ñ": "n", "ÿ": "y", "ø": "o",
    })
    s = s.translate(table)
    return re.sub(r"[^a-z]", "", s)


def _pattern_candidates(first, last, domain):
    """All plausible templates for (first, last) @ domain."""
    f, l = _ascii_slug(first), _ascii_slug(last)
    if not f or not l:
        return []
    return [
        f"{f}.{l}@{domain}",
        f"{f}@{domain}",
        f"{f[0]}{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{f[0]}.{l}@{domain}",
        f"{f}{l[0]}@{domain}",
        f"{f}_{l}@{domain}",
        f"{l}.{f}@{domain}",
        f"{l}@{domain}",
        f"{l}{f}@{domain}",
    ]


def _infer_patterns(known_emails, domain):
    """Infer email pattern templates from already-verified (email, name) pairs.
    Returns templates ordered by frequency."""
    hits = []
    for email, name in known_emails:
        if "@" not in email or not name:
            continue
        local = email.split("@")[0].lower()
        parts = [p for p in re.split(r"[\s\-]", name) if len(p) >= 2]
        if len(parts) < 2:
            continue
        first, last = _ascii_slug(parts[0]), _ascii_slug(parts[-1])
        if not first or not last:
            continue
        for template, formatted in (
            ("{f}.{l}",  f"{first}.{last}"),
            ("{f}",      first),
            ("{f}{l}",   f"{first}{last}"),
            ("{fi}{l}",  f"{first[0]}{last}"),
            ("{fi}.{l}", f"{first[0]}.{last}"),
            ("{f}{li}",  f"{first}{last[0]}"),
            ("{f}_{l}",  f"{first}_{last}"),
            ("{l}",      last),
            ("{l}.{f}",  f"{last}.{first}"),
            ("{l}{f}",   f"{last}{first}"),
        ):
            if local == formatted:
                hits.append(template)

    from collections import Counter
    counts = Counter(hits)
    return [t for t, _ in counts.most_common()]


def _apply_template(template, first, last, domain):
    f, l = _ascii_slug(first), _ascii_slug(last)
    if not f or not l:
        return None
    return (template
            .replace("{fi}", f[0])
            .replace("{li}", l[0])
            .replace("{f}", f)
            .replace("{l}", l)) + f"@{domain}"


def source_pattern_brute(domain, scraped_names, known_verified):
    """Generate candidate emails from scraped_names. If we already have
    verified (email, name) pairs, infer the pattern first; else try the top
    3 templates per name. Verify with the lightweight mailcheck/disify API.

    This is the biggest yield multiplier — a team page with 10 names +
    1 verified email often produces 8-10 more verified emails."""
    out = set()
    if not scraped_names:
        return out, "pattern-brute"

    inferred = _infer_patterns(known_verified, domain)
    candidates = []

    for name in scraped_names[:30]:
        parts = [p for p in re.split(r"[\s\-]+", name) if len(p) >= 2]
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        nslug = _ascii_slug(first) + _ascii_slug(last)
        # Skip names we already have an email for
        already = any(
            nslug and nslug in _ascii_slug(e.split("@")[0])
            for e, _ in known_verified
        )
        if already:
            continue
        if inferred:
            cand = _apply_template(inferred[0], first, last, domain)
            if cand:
                candidates.append((cand, name))
        else:
            for p in _pattern_candidates(first, last, domain)[:3]:
                candidates.append((p, name))

    seen = set()
    unique = []
    for e, n in candidates:
        if e not in seen:
            seen.add(e)
            unique.append((e, n))
    unique = unique[:30]
    if not unique:
        return out, "pattern-brute"

    def _check(item):
        email, name = item
        return (email, name, _verify_email_quick(email))

    with ThreadPoolExecutor(max_workers=6) as pool:
        for email, name, ok in pool.map(_check, unique):
            if ok is True:
                out.add((email, name))

    return out, "pattern-brute"


# ══════════════════════════════════════════════════════════════
# ROLE EXTRACTION — scan text near emails for role keywords
# ══════════════════════════════════════════════════════════════
def extract_role_near_email(text, email, window=140):
    """Return a detected role (CEO, Founder, etc.) if found within
    `window` chars of the email in `text`, else None."""
    if not text or not email:
        return None
    idx = text.lower().find(email.lower())
    if idx < 0:
        return None
    start = max(0, idx - window)
    end = min(len(text), idx + len(email) + window)
    window_text = text[start:end]
    m = ROLE_RE.search(window_text)
    if not m:
        return None
    role = m.group(1).strip().lower()
    mapping = {"cofounder": "Co-Founder", "co-founder": "Co-Founder",
               "founder": "Founder", "ceo": "CEO", "cto": "CTO",
               "cfo": "CFO", "coo": "COO", "cmo": "CMO", "cpo": "CPO",
               "cso": "CSO", "gp": "General Partner",
               "general partner": "General Partner",
               "managing director": "Managing Director",
               "vp": "VP", "svp": "SVP", "evp": "EVP",
               "head of": "Head of", "chief": "Chief",
               "partner": "Partner", "president": "President"}
    return mapping.get(role, role.title())


# ══════════════════════════════════════════════════════════════
# MAIN HARVESTER — 18 sources in parallel + pattern brute
# ══════════════════════════════════════════════════════════════
def harvest_domain(domain, verbose=False):
    """Run 18 OSINT sources in parallel, then pattern-brute scraped names,
    then run the full checker on every candidate."""
    all_emails = {}  # email -> {name, sources}
    founders_found = []
    source_counts = {}
    scraped_names = []  # Populated by source_website for pattern brute
    role_hints = {}    # email -> role (from nearby text on team pages)

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
            pool.submit(source_crtsh, domain): "crtsh",
            pool.submit(source_hackernews, domain): "hackernews",
            pool.submit(source_reddit, domain): "reddit",
            pool.submit(source_stackexchange, domain): "stackexchange",
            pool.submit(source_mastodon, domain): "mastodon",
            pool.submit(source_producthunt, domain): "producthunt",
            pool.submit(source_whois, domain): "whois",
            pool.submit(source_sec_edgar, domain): "sec",
        }
        fut_yc = pool.submit(source_yc_patterns, domain)

        for future in as_completed(futures):
            source_name = futures[future]
            try:
                result = future.result(timeout=60)
                emails_set, src = result[0], result[1]
                # source_website returns extras: scraped_names + email_role dict
                if src == "website":
                    if len(result) >= 3:
                        scraped_names.extend(result[2] or [])
                    if len(result) >= 4 and isinstance(result[3], dict):
                        role_hints.update(result[3])
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
        except Exception:
            source_counts["yc-bruteforce"] = 0

    # ── PATTERN BRUTE (biggest yield lever) ──
    # Run AFTER the main pool so we can infer the pattern from any emails
    # already found. Uses the scraped names from source_website.
    if scraped_names:
        known_pairs = [(e, info["name"]) for e, info in all_emails.items()
                       if info.get("name")]
        try:
            brute_emails, brute_src = source_pattern_brute(
                domain, scraped_names, known_pairs)
            source_counts[brute_src] = len(brute_emails)
            for email, name in brute_emails:
                if email not in all_emails:
                    all_emails[email] = {"name": name, "sources": [brute_src]}
                else:
                    all_emails[email]["sources"].append(brute_src)
                    if name and not all_emails[email]["name"]:
                        all_emails[email]["name"] = name
        except Exception as e:
            source_counts["pattern-brute"] = 0
            if verbose:
                print(f"    ⚠️  pattern-brute: {e}")

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

        # Detect role — prefer website role hint, then GitHub, then YC crossref
        poste = role_hints.get(email) or ""
        if not poste and gh_login:
            poste = get_github_role(gh_login) or ""
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
