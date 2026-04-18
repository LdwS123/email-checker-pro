#!/usr/bin/env python3
"""
Mega Email Scraper v3 — VERIFIED real emails
=============================================
Strategy:
  1. Scrape founder names from YC directory (or Crunchbase)
  2. Mine GitHub commits for real emails
  3. Guess email patterns from founder names
  4. Detect catch-all domains → skip SMTP on those
  5. SMTP verify guessed emails on non-catch-all domains
  6. Run theHarvester as backup

Usage:
  python3 mega_scraper.py --domain posthog.com     # single domain test
  python3 mega_scraper.py                          # batch all domains
  python3 mega_scraper.py --no-browser             # skip Playwright (faster)
  GH_TOKEN=ghp_xxx python3 mega_scraper.py         # enable GitHub source
"""
import subprocess, csv, re, time, os, argparse, smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests
import dns.resolver

# ── Config ──────────────────────────────────────────────────
DOMAINS_FILE = "/Users/kokabuildsf/Scrapper/domains_yc_ai.txt"
OUTPUT       = "/Users/kokabuildsf/Scrapper/verified_emails.csv"
DONE_FILE    = "/Users/kokabuildsf/Scrapper/mega_done.txt"

GH_TOKEN = os.environ.get("GH_TOKEN", "")

MAX_REPOS = 8
MAX_COMMITS = 40

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
    "booster", "nfounders", "news", "blog", "docs", "app", "api",
    "status", "events", "community", "store", "shop", "cdn", "static",
    "staging", "prod", "config", "data", "internal", "external",
    "domains", "soporte", "from-quick-form", "guestuser", "psl",
    "dockerfile", "neuralgpt_agent", "server", "local-admin",
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

write_lock = Lock()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml",
})


def is_personal(email, domain):
    if not email or "@" not in email:
        return False
    email = email.strip().lower()
    local, dom = email.split("@", 1)
    # Must match the exact domain (not subdomains like pooler.supabase.com)
    if dom != domain.lower() and dom != f"www.{domain.lower()}":
        return False
    if local in GENERIC_LOCALS:
        return False
    if local.isdigit() or len(local) < 2 or len(local) > 40:
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


# ═══════════════════════════════════════════════════════════
# SOURCE 1: YC Directory — Scrape Founder Names
# ═══════════════════════════════════════════════════════════
_browser = None
_browser_lock = Lock()


def get_browser():
    global _browser
    with _browser_lock:
        if _browser is None:
            from playwright.sync_api import sync_playwright
            pw = sync_playwright().start()
            _browser = pw.chromium.launch(headless=True)
        return _browser


def scrape_yc_founders(domain, use_browser=True):
    """Scrape founder names from YC directory."""
    # Build possible YC slugs from domain
    # e.g., posthog.com → posthog, linear.app → linear, browser-use.com → browser-use
    base = domain.split(".")[0]
    tld = domain.split(".")[-1] if "." in domain else ""
    slugs = [
        base,
        base.replace("-", ""),
        f"{base}-{tld}" if tld not in ("com", "org", "net") else None,
        f"{base}-ai",
        f"{base}ai",
    ]
    slugs = [s for s in slugs if s]

    # Known false positive names from YC page navigation
    NOISE_NAMES = {
        "Active Founders", "Latest News", "Hear From", "Company Jobs",
        "Startup Directory", "Startup Library", "Startup School",
        "Hacker News", "San Francisco", "New York", "Los Angeles",
        "Privacy Policy", "Demo Day", "Terms Service", "Cookie Policy",
        "Apply Now", "Log In", "Sign Up", "Read More", "Learn More",
        "Mountain View", "Palo Alto", "South San", "Silicon Valley",
        "Series Seed", "United States", "United Kingdom",
    }

    # Common YC partner names to exclude (they're not company founders)
    YC_PARTNERS = {
        "Jared Friedman", "Michael Seibel", "Dalton Caldwell",
        "Gustaf Alstromer", "Aaron Epstein", "Brad Flora",
        "Diana Hu", "Harj Taggar", "Kevin Hale", "Kat Manalac",
        "Qasar Younis", "Tim Brady", "Adora Cheung",
        "Geoff Ralston", "Eric Migicovsky", "Garry Tan",
        "Surbhi Sarna", "Pete Koomen", "Anu Hariharan",
    }

    founders = []

    def clean_founders(names):
        """Filter out noise from founder name list."""
        clean = []
        for name in names:
            name = name.strip()
            if name in NOISE_NAMES or name in YC_PARTNERS:
                continue
            # Must have at least 2 words, each 2+ chars
            parts = name.split()
            if len(parts) < 2:
                continue
            if any(len(p) < 2 for p in parts):
                continue
            # Skip if it contains common non-name words
            lower = name.lower()
            if any(w in lower for w in [
                "policy", "school", "library", "directory", "news",
                "francisco", "angeles", "valley", "apply", "sign",
                "demo", "terms", "cookie", "privacy", "startup",
                "series", "states", "kingdom", "more", "log in",
            ]):
                continue
            clean.append(name)
        return clean

    def extract_founders_from_text(text):
        """Extract founder names from YC page text."""
        found = []
        if "Active Founders" in text:
            parts = text.split("Active Founders")
            if len(parts) > 1:
                section = parts[1]
                for cutoff in ["Latest News", "Hear from", "Jobs", "Company"]:
                    if cutoff in section:
                        section = section.split(cutoff)[0]
                        break
                section = section[:1500]
                for line in section.split("\n"):
                    line = line.strip()
                    match = re.match(r"^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})$", line)
                    if match:
                        found.append(match.group(1))
        return found

    if use_browser:
        try:
            browser = get_browser()
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )
            context.set_default_timeout(12000)

            for slug in slugs:
                try:
                    page = context.new_page()
                    page.goto(f"https://www.ycombinator.com/companies/{slug}", wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(2000)
                    text = page.inner_text("body")
                    founders = extract_founders_from_text(text)
                    page.close()
                    if founders:
                        break
                except Exception:
                    try:
                        page.close()
                    except Exception:
                        pass

            context.close()
        except Exception:
            pass

    # Fallback: plain HTTP
    if not founders:
        for s in slugs:
            try:
                r = SESSION.get(f"https://www.ycombinator.com/companies/{s}", timeout=10)
                if r.status_code == 200 and "Active Founders" in r.text:
                    text = r.text
                    parts = text.split("Active Founders")
                    if len(parts) > 1:
                        section = parts[1]
                        for cutoff in ["Latest News", "latestNews", "Hear from"]:
                            if cutoff in section:
                                section = section.split(cutoff)[0]
                                break
                        section = section[:2000]
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(section, "lxml")
                        for el in soup.find_all(["h3", "h4", "div", "span", "p"]):
                            txt = el.get_text(strip=True)
                            match = re.match(r"^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})$", txt)
                            if match:
                                founders.append(match.group(1))
                    if founders:
                        break
            except Exception:
                continue

    founders = clean_founders(founders)

    return list(set(founders))


# ═══════════════════════════════════════════════════════════
# SOURCE 2: Email Pattern Guessing
# ═══════════════════════════════════════════════════════════
def generate_email_patterns(first, last, domain):
    """Generate common email patterns from a name."""
    first = first.lower().strip()
    last = last.lower().strip()
    return [
        f"{first}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{first}_{last}@{domain}",
        f"{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{last}.{first}@{domain}",
    ]


# ═══════════════════════════════════════════════════════════
# SOURCE 3: SMTP Verification + Catch-All Detection
# ═══════════════════════════════════════════════════════════
_mx_cache = {}
_catchall_cache = {}


def get_mx_host(domain):
    if domain in _mx_cache:
        return _mx_cache[domain]
    try:
        records = dns.resolver.resolve(domain, "MX")
        mx = sorted(records, key=lambda r: r.preference)
        host = str(mx[0].exchange).rstrip(".")
        _mx_cache[domain] = host
        return host
    except Exception:
        _mx_cache[domain] = None
        return None


def is_catchall(domain):
    """Test if domain accepts all emails (catch-all)."""
    if domain in _catchall_cache:
        return _catchall_cache[domain]
    mx = get_mx_host(domain)
    if not mx:
        _catchall_cache[domain] = None
        return None
    try:
        with smtplib.SMTP(mx, 25, timeout=10) as smtp:
            smtp.ehlo("check.example.com")
            smtp.mail("test@example.com")
            code, _ = smtp.rcpt(f"zzzfake9876nonexist@{domain}")
            result = code == 250
            _catchall_cache[domain] = result
            return result
    except Exception:
        _catchall_cache[domain] = None
        return None


def verify_email_smtp(email):
    """Verify a single email via SMTP. Returns True/False/None."""
    domain = email.split("@")[1]
    mx = get_mx_host(domain)
    if not mx:
        return None
    try:
        with smtplib.SMTP(mx, 25, timeout=10) as smtp:
            smtp.ehlo("check.example.com")
            smtp.mail("test@example.com")
            code, _ = smtp.rcpt(email)
            return code == 250
    except Exception:
        return None


def guess_and_verify_emails(founders, domain, verbose=False):
    """Guess email patterns for founders and SMTP verify them."""
    verified_emails = set()

    # First check if domain is catch-all
    catchall = is_catchall(domain)
    if verbose:
        if catchall is True:
            print(f"    ⚠️  {domain} is CATCH-ALL — using first-name pattern only (most likely)")
        elif catchall is False:
            print(f"    ✅ {domain} rejects invalid emails — SMTP verification works!")
        else:
            print(f"    ❓ {domain} SMTP check inconclusive")

    for name in founders:
        parts = name.split()
        if len(parts) < 2:
            continue
        first = parts[0]
        last = parts[-1]

        candidates = generate_email_patterns(first, last, domain)

        if catchall is True:
            # Can't verify — just use the most common pattern (firstname@)
            email = f"{first.lower()}@{domain}"
            if is_personal(email, domain):
                verified_emails.add(email)
        elif catchall is False:
            # We can actually verify!
            for email in candidates:
                result = verify_email_smtp(email)
                if result is True:
                    verified_emails.add(email)
                    if verbose:
                        print(f"    ✅ {email} — VERIFIED")
                    break  # Found the right pattern, no need to try more
                time.sleep(0.3)  # Don't hammer the server
        else:
            # Can't connect — just use the most common pattern
            email = f"{first.lower()}@{domain}"
            if is_personal(email, domain):
                verified_emails.add(email)

    return verified_emails


# ═══════════════════════════════════════════════════════════
# SOURCE 4: GitHub Commits
# ═══════════════════════════════════════════════════════════
GH_SESSION = requests.Session()
if GH_TOKEN:
    GH_SESSION.headers.update({
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    })


def gh_get(url, params=None):
    if not GH_TOKEN:
        return None
    for attempt in range(3):
        try:
            r = GH_SESSION.get(url, params=params, timeout=15)
            if r.status_code == 403:
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time(), 1)
                time.sleep(min(wait + 1, 90))
                continue
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


def find_github_org(domain):
    base = domain.split(".")[0]
    candidates = [
        base, base.replace("-", ""), base + "ai", base + "-ai",
        base + "hq", base + "inc", base + "io", domain.replace(".", "-"),
    ]
    for candidate in candidates:
        data = gh_get(f"https://api.github.com/orgs/{candidate}")
        if data and "login" in data:
            return data["login"], "org"
        data = gh_get(f"https://api.github.com/users/{candidate}")
        if data and data.get("type") in ("User", "Organization"):
            return data["login"], data["type"].lower()
    return None, None


def mine_github_commits(domain):
    if not GH_TOKEN:
        return set()
    emails = set()
    login, entity_type = find_github_org(domain)
    if not login:
        return emails

    url = (f"https://api.github.com/orgs/{login}/repos"
           if entity_type in ("org", "organization")
           else f"https://api.github.com/users/{login}/repos")

    repos = gh_get(url, params={"per_page": MAX_REPOS, "sort": "pushed", "type": "public"})
    if not isinstance(repos, list):
        return emails

    for repo in repos[:MAX_REPOS]:
        repo_name = repo.get("full_name", "")
        if not repo_name:
            continue
        commits = gh_get(
            f"https://api.github.com/repos/{repo_name}/commits",
            params={"per_page": MAX_COMMITS},
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
                    if is_personal(email, domain):
                        emails.add(email.strip().lower())
            except Exception:
                pass
    return emails


# ═══════════════════════════════════════════════════════════
# SOURCE 5: theHarvester
# ═══════════════════════════════════════════════════════════
def run_theharvester(domain):
    emails = set()
    sources = ["github-code", "hackertarget", "rapiddns", "subdomaincenter"]
    for source in sources:
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-b", source, "-l", "200"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            found = extract_emails(output, domain)
            emails.update(found)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return emails


# ═══════════════════════════════════════════════════════════
# SOURCE 6: Website crawl (with browser)
# ═══════════════════════════════════════════════════════════
TEAM_PATHS = [
    "/about", "/about-us", "/team", "/people", "/company",
    "/contact", "/founders", "/leadership", "/",
]


def crawl_website(domain, use_browser=True):
    """Crawl website pages for emails."""
    emails = set()

    if use_browser:
        try:
            browser = get_browser()
            context = browser.new_context()
            context.set_default_timeout(10000)
            for path in TEAM_PATHS:
                url = f"https://{domain}{path}"
                try:
                    page = context.new_page()
                    resp = page.goto(url, wait_until="networkidle", timeout=12000)
                    if resp and resp.status == 200:
                        page.wait_for_timeout(1500)
                        content = page.content()
                        found = extract_emails(content, domain)
                        emails.update(found)
                        text = page.inner_text("body")
                        found2 = extract_emails(text, domain)
                        emails.update(found2)
                    page.close()
                except Exception:
                    try:
                        page.close()
                    except Exception:
                        pass
                if emails:
                    break
            context.close()
        except Exception:
            pass

    # Fallback: plain HTTP
    if not emails:
        for base in [f"https://{domain}", f"https://www.{domain}"]:
            for path in TEAM_PATHS:
                try:
                    r = SESSION.get(base + path, timeout=8)
                    if r.status_code == 200:
                        found = extract_emails(r.text, domain)
                        emails.update(found)
                except Exception:
                    continue
            if emails:
                break

    return emails


# ═══════════════════════════════════════════════════════════
# Main Harvester
# ═══════════════════════════════════════════════════════════
def harvest_domain(domain, use_browser=True, verbose=False):
    """Harvest VERIFIED emails from all sources."""
    all_emails = set()
    sources = {}

    # Step 1: Get founder names from YC
    if verbose:
        print(f"  [1/5] Scraping YC for founder names...")
    founders = scrape_yc_founders(domain, use_browser=use_browser)
    if verbose:
        if founders:
            print(f"    Found founders: {', '.join(founders)}")
        else:
            print(f"    No founders found on YC directory")

    # Step 2: Guess + verify emails from founder names
    if founders:
        if verbose:
            print(f"  [2/5] Guessing email patterns + SMTP verifying...")
        guessed = guess_and_verify_emails(founders, domain, verbose=verbose)
        all_emails.update(guessed)
        sources["guessed"] = len(guessed)
    else:
        sources["guessed"] = 0

    # Step 3: GitHub commits
    if GH_TOKEN:
        if verbose:
            print(f"  [3/5] Mining GitHub commits...")
        gh_emails = mine_github_commits(domain)
        all_emails.update(gh_emails)
        sources["github"] = len(gh_emails)
    else:
        sources["github"] = 0

    # Step 4: theHarvester
    if verbose:
        print(f"  [4/5] Running theHarvester...")
    th_emails = run_theharvester(domain)
    all_emails.update(th_emails)
    sources["harvester"] = len(th_emails)

    # Step 5: Website crawl
    if verbose:
        print(f"  [5/5] Crawling website...")
    web_emails = crawl_website(domain, use_browser=use_browser)
    all_emails.update(web_emails)
    sources["website"] = len(web_emails)

    # Build results with verification status — skip invalid emails
    catchall = is_catchall(domain)
    results = []
    for email in sorted(all_emails):
        if catchall is False:
            v = verify_email_smtp(email)
            if v is False:
                continue  # Skip confirmed invalid emails
            status = "verified" if v is True else "unknown"
        elif catchall is True:
            status = "catch-all"
        else:
            status = "unknown"
        results.append({
            "domain": domain,
            "email": email,
            "status": status,
            "source": _identify_source(email, sources, domain),
        })

    return domain, results, sources, founders


def _identify_source(email, sources_counts, domain):
    """Best-effort source identification."""
    # This is approximate — we just label by what's available
    return "multi-source"


def load_done():
    if os.path.exists(DONE_FILE):
        with open(DONE_FILE) as f:
            return {l.strip() for l in f if l.strip()}
    return set()


def save_done(domain):
    with open(DONE_FILE, "a") as f:
        f.write(domain + "\n")


def main():
    parser = argparse.ArgumentParser(description="Mega Email Scraper v3")
    parser.add_argument("--domain", help="Scrape a single domain")
    parser.add_argument("--domains-file", default=DOMAINS_FILE)
    parser.add_argument("--output", default=OUTPUT)
    parser.add_argument("--no-browser", action="store_true", help="Skip Playwright")
    parser.add_argument("--reset", action="store_true", help="Reset done list")
    args = parser.parse_args()

    use_browser = not args.no_browser

    if args.reset and os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)
        print("  Reset done list")

    # ── Single domain ──
    if args.domain:
        print(f"\n{'='*60}")
        print(f"  MEGA SCRAPER v3 — {args.domain}")
        print(f"{'='*60}")
        domain, results, sources, founders = harvest_domain(
            args.domain, use_browser=use_browser, verbose=True
        )
        print(f"\n  Founders found: {founders or 'none'}")
        print(f"\n  Sources breakdown:")
        for src, count in sources.items():
            icon = "+" if count > 0 else "-"
            print(f"    [{icon}] {src:12s}: {count} emails")
        print(f"\n  Total unique: {len(results)} emails")
        print("-" * 60)
        for r in results:
            print(f"  {r['email']:40s} [{r['status']}]")
        print("=" * 60)

        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "email", "status", "source"])
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"  Saved to {args.output}")
        return

    # ── Batch mode ──
    with open(args.domains_file) as f:
        all_domains = [l.strip() for l in f if l.strip()]

    done = load_done()
    todo = [d for d in all_domains if d not in done]

    print(f"\n{'='*60}")
    print(f"  MEGA EMAIL SCRAPER v3")
    print(f"{'='*60}")
    print(f"  Total domains  : {len(all_domains)}")
    print(f"  Already done   : {len(done)}")
    print(f"  Remaining      : {len(todo)}")
    print(f"  Browser        : {'YES' if use_browser else 'NO'}")
    print(f"  GitHub token   : {'SET' if GH_TOKEN else 'NOT SET'}")
    print(f"  Output         : {args.output}")
    print(f"{'='*60}\n")

    if not todo:
        print("  Nothing to do!")
        return

    found_total = 0
    processed = 0
    domains_with_emails = 0

    file_exists = os.path.exists(args.output) and os.path.getsize(args.output) > 10
    mode = "a" if file_exists else "w"

    with open(args.output, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain", "email", "status", "source"])
        if not file_exists:
            writer.writeheader()

        for domain in todo:
            _, results, sources, founders = harvest_domain(
                domain, use_browser=use_browser, verbose=False
            )
            processed += 1
            save_done(domain)

            if results:
                with write_lock:
                    for r in results:
                        writer.writerow(r)
                    fh.flush()
                found_total += len(results)
                domains_with_emails += 1
                src_str = " | ".join(f"{k}:{v}" for k, v in sources.items() if v > 0)
                founders_str = f" founders={','.join(founders)}" if founders else ""
                print(f"[{processed:>4}/{len(todo)}] ✅ {domain:25s} +{len(results):>3} ({src_str}){founders_str}")
            else:
                print(f"[{processed:>4}/{len(todo)}] ❌ {domain:25s}")

    print(f"\n{'='*60}")
    print(f"  DONE")
    print(f"  Domains processed   : {processed}")
    print(f"  Domains with emails : {domains_with_emails}")
    print(f"  Total emails found  : {found_total}")
    print(f"  Saved to            : {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
