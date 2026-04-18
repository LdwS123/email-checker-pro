#!/usr/bin/env python3
"""
YC AI Founder Email Finder
Strategy: GitHub commit history (real emails) → website HTML → email pattern guess
Apollo free plan is blocked, so GitHub is the primary source.
"""

import csv
import re
import time
import json
import os
import requests
from bs4 import BeautifulSoup

# ── Config ─────────────────────────────────────────────────────────────────────
OUTPUT_FILE = "founder_emails.csv"
DELAY = 0.8  # seconds between requests

GH_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0",
    "Authorization": f"token {os.environ.get('GH_TOKEN', '')}",
}
WEB_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

GENERIC_PREFIXES = {
    "info", "hello", "contact", "support", "admin", "team", "sales",
    "help", "privacy", "legal", "press", "hr", "jobs", "careers",
    "hi", "mail", "noreply", "no-reply", "billing", "security",
}
BOT_NAMES = {"github-actions", "dependabot", "renovate", "bot", "action"}

# ── Company list ───────────────────────────────────────────────────────────────
# Each entry: (domain, company_name, known_github_org_or_None)
COMPANIES = [
    ("wordware.ai",       "Wordware",        "wordware-ai"),
    ("gumloop.com",       "Gumloop",         "gumloop"),
    ("firecrawl.dev",     "Firecrawl",       "mendableai"),
    ("e2b.dev",           "E2B",             "e2b-dev"),
    ("lindy.ai",          "Lindy",           None),
    ("relevanceai.com",   "Relevance AI",    "RelevanceAI"),
    ("composio.dev",      "Composio",        "ComposioHQ"),
    ("theagi.company",    "MultiOn",         "MULTI-ON"),
    ("induced.ai",        "Induced AI",      None),
    ("ema.ai",            "Ema",             None),
    ("relay.app",         "Relay",           None),
    ("vapi.ai",           "Vapi AI",         "VapiAI"),
    ("windsurf.com",      "Windsurf",        None),
    ("humanloop.com",     "Humanloop",       "humanloop"),
    ("inventive.ai",      "Inventive AI",    None),
    ("emergence.ai",      "Emergence AI",    None),
    ("agentuity.com",     "Agentuity",       None),
    ("dodo.ai",           "Dodo",            None),
    ("letta.com",         "Letta",           "letta-ai"),
    ("trypulse.ai",       "Pulse AI",        None),
    ("calltree.ai",       "Calltree",        None),
    ("rowboatlabs.com",   "Rowboat Labs",    "rowboatlabs"),
    ("usebrainbase.xyz",  "Brainbase",       None),
    ("eloquentai.co",     "Eloquent AI",     None),
    ("tallyhq.com",       "Tally",           None),
    ("fazeshift.com",     "Fazeshift",       None),
    ("getpathpilot.com",  "PathPilot",       None),
    ("agentmail.cc",      "AgentMail",       "agentmail-toolkit"),
    ("pibit.ai",          "Pibit",           None),
    ("getbluebook.com",   "Bluebook",        None),
    ("sennu.ai",          "Sennu AI",        None),
    ("agenthub.dev",      "AgentHub",        None),
    ("ironledger.ai",     "IronLedger",      None),
    ("tryjanet.ai",       "Janet AI",        None),
    ("cyberdesk.io",      "Cyberdesk",       "cyberdesk-io"),
    ("getsocratix.ai",    "Socratix AI",     None),
    ("tryghostship.dev",  "Ghostship",       None),
    ("rowflow.ai",        "RowFlow",         None),
    ("bland.ai",          "Bland AI",        "BLAND-AI"),
    ("cassidyai.com",     "Cassidy AI",      None),
    ("cognition.ai",      "Cognition AI",    "cognition-ai"),
    ("crewai.com",        "CrewAI",          "crewAIInc"),
    ("browser-use.com",   "Browser Use",     "browser-use"),
    ("dust.tt",           "Dust",            "dust-tt"),
    ("mindy.ai",          "Mindy AI",        None),
    ("julius.ai",         "Julius AI",       None),
    ("beam.ai",           "Beam AI",         None),
    ("agno.com",          "Agno",            "agno-agi"),
    ("superagent.sh",     "Superagent",      "homanp"),
    ("slashy.ai",         "Slashy",          None),
    ("withkeystone.com",  "Keystone",        None),
    ("doe.so",            "Doe",             None),
    ("closera.ai",        "Closera",         None),
    ("comena.ai",         "Comena",          None),
    ("candytrail.io",     "Candytrail",      None),
    ("tryasync.ai",       "Async",           None),
    ("fulcrum.run",       "Fulcrum",         None),
    ("agentin.ai",        "Agentin AI",      None),
    ("kater.ai",          "Kater AI",        None),
    ("8flow.ai",          "8Flow",           None),
    ("bricklayer.ai",     "Bricklayer AI",   None),
    ("agenticfabriq.com", "Agentic Fabriq",  None),
    ("okibi.ai",          "Okibi",           None),
    ("furtherai.com",     "Further AI",      None),
    ("carecycle.ai",      "CareCycle",       None),
    ("spurtest.com",      "Spur",            "UseSpur"),
    ("dimely.com",        "Dimely",          None),
    ("qeen.ai",           "Qeen",            None),
    ("arcline-ai.com",    "Arcline AI",      None),
    ("sphinxhq.com",      "SphinxHQ",        None),
    ("corvera.ai",        "Corvera",         None),
    ("toothy.ai",         "Toothy AI",       None),
    ("sre.ai",            "SRE AI",          None),
    ("eigenpal.com",      "EigenPal",        None),
    ("syntropy.io",       "Syntropy",        None),
    ("copycat.dev",       "Copycat",         None),
    ("caseflood.ai",      "Caseflood",       None),
    ("parahelp.com",      "Parahelp",        None),
    ("certus-ai.com",     "Certus AI",       None),
    ("arva.ai",           "Arva AI",         None),
    ("jinba.ai",          "Jinba AI",        None),
    ("hyperwriteai.com",  "HyperWrite AI",   None),
    ("getsidekick.ai",    "Sidekick",        None),
    ("datafruit.io",      "Datafruit",       None),
    ("dedaluslabs.com",   "Dedalus Labs",    None),
    ("effigov.com",       "EffiGov",         None),
    ("finto.ai",          "Finto",           None),
    ("floot.ai",          "Floot",           None),
    ("tryalter.com",      "Alter",           None),
    ("browserbase.com",   "Browserbase",     "browserbase"),
    ("modal.com",         "Modal",           "modal-labs"),
    ("reworkd.ai",        "Reworkd",         "reworkd"),
    ("durable.co",        "Durable",         None),
    ("recall.ai",         "Recall AI",       "recallai"),
    ("braintrustdata.com","Braintrust",       "brainlid"),
    ("fixie.ai",          "Fixie AI",        "fixie-ai"),
    ("getsid.ai",         "Sid",             None),
    ("kortex.ai",         "Kortex",          None),
    ("trymemory.ai",      "Memory AI",       None),
    ("stagehand.dev",     "Stagehand",       "browserbase"),
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def is_bot(name):
    n = name.lower()
    return any(b in n for b in BOT_NAMES)


def is_generic(email):
    local = email.split("@")[0].lower()
    return local in GENERIC_PREFIXES


def score_email(email, domain):
    """Higher = more likely a personal founder email."""
    if "@" not in email:
        return 0
    score = 0
    local, dom = email.lower().split("@", 1)
    # Matches company domain exactly
    if domain.lower() in dom:
        score += 10
    # Short local part = likely a name (e.g. filip@, nick@)
    if len(local) <= 12:
        score += 3
    # Contains a dot = firstname.lastname@
    if "." in local:
        score += 2
    return score


# ── GitHub: search for org repos then mine commits ────────────────────────────

def github_get(url):
    try:
        r = requests.get(url, headers=GH_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 403:
            print("  [GH] Rate limited")
    except Exception as e:
        print(f"  [GH] Error: {e}")
    return None


def find_github_repos(org_hint, domain):
    """Return list of repo full_names to check."""
    repos = []
    # 1. Try known org
    if org_hint:
        data = github_get(f"https://api.github.com/orgs/{org_hint}/repos?per_page=10&sort=updated")
        if data:
            repos = [r["full_name"] for r in data if not r.get("fork")]
    # 2. Search GitHub by domain keyword
    if not repos:
        company_keyword = domain.split(".")[0]
        data = github_get(
            f"https://api.github.com/search/repositories?q={company_keyword}&sort=stars&per_page=5"
        )
        if data:
            repos = [r["full_name"] for r in data.get("items", [])
                     if company_keyword.lower() in r["full_name"].lower()]
    return repos[:5]  # cap at 5 repos


def emails_from_commits(repo_full_name, domain):
    """Mine commit history for personal emails."""
    data = github_get(
        f"https://api.github.com/repos/{repo_full_name}/commits?per_page=30"
    )
    if not data or not isinstance(data, list):
        return []

    candidates = {}
    for commit in data:
        c = commit.get("commit", {})
        author = c.get("author", {})
        email = author.get("email", "")
        name = author.get("name", "")
        if not email or is_bot(name) or is_generic(email):
            continue
        if "noreply" in email:
            continue
        if email not in candidates:
            candidates[email] = (name, score_email(email, domain))

    # Sort by score descending
    ranked = sorted(candidates.items(), key=lambda x: x[1][1], reverse=True)
    return [(email, name, score) for email, (name, score) in ranked]


# ── Website scraping ───────────────────────────────────────────────────────────

def scrape_page_emails(url, domain):
    try:
        r = requests.get(url, headers=WEB_HEADERS, timeout=8, allow_redirects=True)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        found = set(EMAIL_RE.findall(r.text))
        for tag in soup.find_all("a", href=re.compile(r"^mailto:")):
            href = tag["href"].replace("mailto:", "").split("?")[0].strip()
            if "@" in href:
                found.add(href)
        return [e for e in found
                if not is_generic(e) and domain.split(".")[0] in e.lower()]
    except Exception:
        return []


def scrape_website(domain):
    for path in ["/team", "/about", "/about-us", "/contact", ""]:
        emails = scrape_page_emails(f"https://{domain}{path}", domain)
        if emails:
            return emails[0]
        time.sleep(0.3)
    return None


# ── Main per-company logic ─────────────────────────────────────────────────────

def process(domain, company_name, gh_org):
    print(f"  [{company_name}] {domain}", end="")

    # 1. GitHub commits
    repos = find_github_repos(gh_org, domain)
    for repo in repos:
        hits = emails_from_commits(repo, domain)
        if hits:
            email, name, _ = hits[0]
            print(f" → GitHub ({repo}): {name} <{email}>")
            return name, "founder/contributor", email, f"github:{repo}"
        time.sleep(DELAY)

    # 2. Website scraping
    email = scrape_website(domain)
    if email:
        print(f" → Scrape: {email}")
        return "", "", email, "scrape"

    print(" → not found")
    return "", "", "", "not_found"


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    stats = {"github": 0, "scrape": 0, "not_found": 0}
    rows = []

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["company", "domain", "founder_name", "founder_title", "email", "source"],
        )
        writer.writeheader()

        for i, (domain, name, gh_org) in enumerate(COMPANIES, 1):
            print(f"[{i:>3}/{len(COMPANIES)}]", end=" ")
            fn, ft, email, source = process(domain, name, gh_org)

            row = {
                "company": name,
                "domain": domain,
                "founder_name": fn,
                "founder_title": ft,
                "email": email,
                "source": source,
            }
            writer.writerow(row)
            f.flush()
            rows.append(row)

            if source.startswith("github"):
                stats["github"] += 1
            elif source == "scrape":
                stats["scrape"] += 1
            else:
                stats["not_found"] += 1

            time.sleep(DELAY)

    total_found = len([r for r in rows if r["email"]])
    print(f"\n{'='*55}")
    print(f"  Total companies  : {len(COMPANIES)}")
    print(f"  Emails found     : {total_found}")
    print(f"  └─ via GitHub    : {stats['github']}")
    print(f"  └─ via Scraping  : {stats['scrape']}")
    print(f"  Not found        : {stats['not_found']}")
    print(f"  CSV saved to     : {OUTPUT_FILE}")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
