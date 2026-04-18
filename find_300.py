#!/usr/bin/env python3
"""
Step 1 — Build a list of 300 AI agent companies from public sources
Step 2 — Find founder emails via GitHub commits + website scraping
"""

import csv, re, time, base64, os, requests
from bs4 import BeautifulSoup

GH = {
    "Authorization": f"token {os.environ.get('GH_TOKEN', '')}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0",
}
WEB = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}

SKIP_DOMAINS = {
    "github.com","twitter.com","x.com","linkedin.com","youtube.com","discord.gg",
    "discord.com","arxiv.org","medium.com","notion.so","docs.","huggingface.co",
    "openai.com","anthropic.com","google.com","reddit.com","producthunt.com",
    "npm.js","pypi.org","t.co","bit.ly","cal.com","loom.com","slack.com",
    "microsoft.com","aws.amazon","azure.","vercel.app","netlify.app",
    "substack.com","dev.to","hashnode","instagram.com","facebook.com",
    "tiktok.com","crunchbase.com","techcrunch.com","wired.com","forbes.com",
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
GENERIC = {"info","hello","contact","support","admin","team","sales","help",
           "privacy","legal","press","hr","jobs","careers","hi","mail",
           "noreply","no-reply","billing","security","founders","investor",
           "partnerships","partnership","media","feedback"}
BOT_NAMES = {"github-actions","dependabot","renovate","bot","action","ci"}

# ── Source 1: GitHub awesome lists ────────────────────────────────────────────

AWESOME_REPOS = [
    "e2b-dev/awesome-ai-agents",
    "kyrolabs/awesome-agents",
    "slavakurilyak/awesome-ai-agents",
    "Jenqyang/Awesome-AI-Agents",
    "tmgthb/Autonomous-Agents",
    "hyp1231/awesome-llm-powered-agent",
    "TechwithTy/Awesome-Agent-Frameworks",
]

def fetch_readme_companies(repo):
    r = requests.get(f"https://api.github.com/repos/{repo}/readme", headers=GH, timeout=12)
    if r.status_code != 200:
        return {}
    content = base64.b64decode(r.json()["content"]).decode("utf-8", errors="ignore")
    links = re.findall(r'\[([^\]]{2,60})\]\(https?://([^/\)\s]+)', content)
    found = {}
    for name, domain in links:
        domain = domain.strip().lower().rstrip(".")
        name = name.strip()
        if not name or not domain or "." not in domain:
            continue
        if any(s in domain for s in SKIP_DOMAINS):
            continue
        if len(domain) > 60 or len(name) > 80:
            continue
        # Skip pure docs/blog subdomains
        if domain.startswith(("docs.","blog.","api.","status.","help.")):
            continue
        if name not in found:
            found[name] = domain
    return found


# ── Source 2: GitHub topic search ─────────────────────────────────────────────

def fetch_github_topic(topic, pages=3):
    found = {}
    for page in range(1, pages + 1):
        r = requests.get(
            f"https://api.github.com/search/repositories?q=topic:{topic}&sort=stars&per_page=30&page={page}",
            headers=GH, timeout=12
        )
        if r.status_code != 200:
            break
        for repo in r.json().get("items", []):
            hp = repo.get("homepage", "") or ""
            hp = hp.strip().lower()
            if hp and hp.startswith("http"):
                domain = re.sub(r"https?://", "", hp).split("/")[0].strip()
                if domain and "." in domain and not any(s in domain for s in SKIP_DOMAINS):
                    name = repo.get("name", domain).replace("-", " ").title()
                    if name not in found:
                        found[name] = domain
        time.sleep(0.3)
    return found


# ── Source 3: Product Hunt scrape ─────────────────────────────────────────────

def fetch_producthunt_agents():
    found = {}
    for page in [1, 2, 3]:
        r = requests.get(
            f"https://www.producthunt.com/search?q=ai+agent&page={page}",
            headers=WEB, timeout=10
        )
        if r.status_code != 200:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "/posts/" in href:
                name = link.get_text(strip=True)
                if name and len(name) < 60:
                    found[name] = None  # domain TBD
        time.sleep(0.5)
    return found


# ── Build master list ─────────────────────────────────────────────────────────

def build_company_list(target=320):
    companies = {}

    print("=== PHASE 1: Collecting companies ===\n")

    # Awesome GitHub lists
    for repo in AWESOME_REPOS:
        batch = fetch_readme_companies(repo)
        new = {k: v for k, v in batch.items() if k not in companies}
        companies.update(new)
        print(f"  {repo}: +{len(new)} (total {len(companies)})")
        time.sleep(0.4)
        if len(companies) >= target:
            break

    # GitHub topic search if needed
    if len(companies) < target:
        for topic in ["ai-agents", "llm-agent", "autonomous-agents", "ai-agent"]:
            batch = fetch_github_topic(topic, pages=2)
            new = {k: v for k, v in batch.items() if k not in companies}
            companies.update(new)
            print(f"  topic:{topic}: +{len(new)} (total {len(companies)})")
            time.sleep(0.5)
            if len(companies) >= target:
                break

    print(f"\nTotal companies collected: {len(companies)}")
    return companies


# ── Email finding ─────────────────────────────────────────────────────────────

def gh_get(url):
    try:
        r = requests.get(url, headers=GH, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        pass
    return None


def find_github_repos(domain):
    keyword = domain.split(".")[0].lower()
    # Search GitHub for repos matching this keyword
    data = gh_get(
        f"https://api.github.com/search/repositories?q={keyword}+in:name&sort=stars&per_page=5"
    )
    if not data:
        return []
    # Only return repos where the org/user name matches the keyword closely
    repos = []
    for item in data.get("items", []):
        fn = item["full_name"].lower()
        org = fn.split("/")[0]
        if keyword in org or keyword in fn.split("/")[1]:
            repos.append(item["full_name"])
    return repos[:3]


def is_bot(name):
    return any(b in name.lower() for b in BOT_NAMES)


def score_email(email, domain):
    if "@" not in email:
        return 0
    score = 0
    local, dom = email.lower().split("@", 1)
    if domain.lower() in dom:
        score += 20   # company domain = very high
    if len(local) <= 15:
        score += 3
    if "." in local:
        score += 2
    return score


def emails_from_commits(repo, domain):
    data = gh_get(f"https://api.github.com/repos/{repo}/commits?per_page=30")
    if not data or not isinstance(data, list):
        return []
    candidates = {}
    for commit in data:
        c = commit.get("commit", {})
        author = c.get("author", {})
        email = author.get("email", "")
        name = author.get("name", "")
        if not email or "@" not in email or is_bot(name):
            continue
        if "noreply" in email or "Mac.localdomain" in email:
            continue
        local = email.split("@")[0].lower()
        if local in GENERIC:
            continue
        if email not in candidates:
            candidates[email] = (name, score_email(email, domain))
    return sorted(candidates.items(), key=lambda x: x[1][1], reverse=True)


def scrape_email(domain):
    for path in ["/team", "/about", "/about-us", "/contact", ""]:
        try:
            r = requests.get(f"https://{domain}{path}", headers=WEB, timeout=7, allow_redirects=True)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            found = set(EMAIL_RE.findall(r.text))
            for tag in soup.find_all("a", href=re.compile(r"^mailto:")):
                href = tag["href"].replace("mailto:", "").split("?")[0].strip()
                if "@" in href:
                    found.add(href)
            # Only personal emails on company domain
            personal = [
                e for e in found
                if "@" in e
                and domain.split(".")[0] in e.lower()
                and e.split("@")[0].lower() not in GENERIC
                and "." in e.split("@")[-1]
                and "Mac.localdomain" not in e
            ]
            if personal:
                return personal[0]
        except Exception:
            pass
        time.sleep(0.2)
    return None


def process_company(name, domain):
    # 1. Try GitHub commit mining
    repos = find_github_repos(domain)
    for repo in repos:
        hits = emails_from_commits(repo, domain)
        if hits:
            email, (cname, score) = hits[0]
            confidence = "high" if score >= 20 else "medium"
            return cname, email, f"github:{repo}", confidence
        time.sleep(0.4)

    # 2. Try website scraping
    email = scrape_email(domain)
    if email:
        return "", email, "scrape", "high"

    return "", "", "not_found", "-"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    companies = build_company_list(target=320)

    # Take up to 300, sorted alphabetically for reproducibility
    company_list = sorted(companies.items())[:300]

    print(f"\n=== PHASE 2: Finding emails for {len(company_list)} companies ===\n")

    OUTPUT = "agents_300_emails.csv"
    stats = {"high": 0, "medium": 0, "not_found": 0}

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["company","domain","founder_name","email","source","confidence"]
        )
        writer.writeheader()

        for i, (name, domain) in enumerate(company_list, 1):
            print(f"[{i:>3}/300] {name[:30]:30s} ({domain})", end=" ")
            fn, email, source, conf = process_company(name, domain)
            print(f"→ {email or 'not found'}")

            writer.writerow({
                "company": name, "domain": domain,
                "founder_name": fn, "email": email,
                "source": source, "confidence": conf,
            })
            f.flush()
            stats[conf if conf != "-" else "not_found"] = stats.get(conf if conf != "-" else "not_found", 0) + 1
            time.sleep(0.6)

    found = stats.get("high", 0) + stats.get("medium", 0)
    print(f"\n{'='*60}")
    print(f"  Total companies  : {len(company_list)}")
    print(f"  Emails found     : {found}")
    print(f"  HIGH confidence  : {stats.get('high', 0)}")
    print(f"  MEDIUM confidence: {stats.get('medium', 0)}")
    print(f"  Not found        : {stats.get('not_found', 0)}")
    print(f"  Saved to         : {OUTPUT}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
