#!/usr/bin/env python3
"""
Email harvester via GitHub commit API (core rate: 5000 req/h)
Pour chaque domaine : cherche l'org GitHub → liste les repos → mine les commits
"""
import requests, csv, time, os, re, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

GH_TOKEN = os.environ.get("GH_TOKEN", "")
HEADERS = {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"}

DOMAINS_FILE = "/Users/kokabuildsf/Scrapper/domains_yc_ai.txt"
OUTPUT       = "/Users/kokabuildsf/Scrapper/founders_emails.csv"
DONE_FILE    = "/Users/kokabuildsf/Scrapper/founders_done.txt"

WORKERS = 4
MAX_REPOS = 10     # repos par org
MAX_COMMITS = 50   # commits par repo

GENERIC = {
    "support","hello","info","contact","team","press","privacy","legal",
    "security","hr","jobs","careers","noreply","no-reply","billing","sales",
    "help","admin","founders","founder","server","sandbox","demo","devops",
    "dev","devs","bot","guest","test1","test2","local-admin","feedback",
    "flow","booster","ai","notify","notifications","alerts","webhook",
    "ops","infra","engineering","product","design","marketing","finance",
    "accounting","payroll","invoice","git","github","gitlab","action",
}

write_lock = Lock()

SESSION = requests.Session()
SESSION.headers.update(HEADERS)


def gh_get(url, params=None):
    for attempt in range(3):
        try:
            r = SESSION.get(url, params=params, timeout=15)
            if r.status_code == 403:
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time(), 1)
                print(f"  [rate limit] sleeping {wait:.0f}s")
                time.sleep(min(wait + 1, 120))
                continue
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except Exception as e:
            time.sleep(2 * (attempt + 1))
    return None


def find_org_for_domain(domain):
    """Cherche l'org GitHub pour ce domaine.
    Méthode 1: nom d'org = partie avant le TLD (e2b.dev → e2b)
    Méthode 2: cherche via l'API users/orgs par nom
    """
    # Strip TLD: e2b.dev → e2b, langchain.com → langchain
    name_parts = domain.split(".")
    base = name_parts[0]  # partie principale
    # Essaie aussi variantes: e2b-dev, langchainai, etc.
    candidates = [
        base,
        base.replace("-", ""),
        domain.replace(".", "-"),
        base + "ai",
        base + "-ai",
    ]
    for candidate in candidates:
        # Essaie org
        data = gh_get(f"https://api.github.com/orgs/{candidate}")
        if data and "login" in data:
            return data["login"], "org"
        # Essaie user
        data = gh_get(f"https://api.github.com/users/{candidate}")
        if data and data.get("type") in ("User", "Organization"):
            return data["login"], data["type"].lower()
    return None, None


def get_repos(login, entity_type):
    if entity_type == "org":
        url = f"https://api.github.com/orgs/{login}/repos"
    else:
        url = f"https://api.github.com/users/{login}/repos"
    data = gh_get(url, params={"per_page": MAX_REPOS, "sort": "pushed", "type": "public"})
    return data if isinstance(data, list) else []


def is_personal(email, domain):
    if not email or "@" not in email:
        return False
    email = email.strip().lstrip("'\"").lower()
    if " " in email or "," in email:
        return False
    local, dom = email.split("@", 1)
    # L'email doit appartenir au domaine cible
    if domain.lower() not in dom:
        return False
    if local in GENERIC:
        return False
    if local.isdigit():
        return False
    if "localdomain" in email or "noreply" in email or "github" in email:
        return False
    if len(local) < 2 or len(local) > 40:
        return False
    # Filtre les patterns non-humains: v1.0.0@, release-bot@, etc.
    if re.search(r'\d{3,}|bot|robot|auto|build|ci|cd|deploy|release|action', local):
        return False
    return True


def mine_commits(repo_full_name, domain):
    """Mine les emails dans les commits d'un repo."""
    emails = set()
    data = gh_get(
        f"https://api.github.com/repos/{repo_full_name}/commits",
        params={"per_page": MAX_COMMITS}
    )
    if not isinstance(data, list):
        return emails
    for commit in data:
        try:
            author = commit.get("commit", {}).get("author", {})
            committer = commit.get("commit", {}).get("committer", {})
            for person in [author, committer]:
                email = person.get("email", "")
                if is_personal(email, domain):
                    emails.add(email.strip().lower())
        except Exception:
            pass
    return emails


def harvest_domain(domain):
    try:
        login, entity_type = find_org_for_domain(domain)
        if not login:
            return domain, []
        repos = get_repos(login, entity_type)
        if not repos:
            return domain, []
        all_emails = set()
        for repo in repos[:MAX_REPOS]:
            repo_name = repo.get("full_name", "")
            if not repo_name:
                continue
            emails = mine_commits(repo_name, domain)
            all_emails.update(emails)
        return domain, list(all_emails)
    except Exception as e:
        return domain, []


def load_done():
    if os.path.exists(DONE_FILE):
        with open(DONE_FILE) as f:
            return {l.strip() for l in f if l.strip()}
    return set()


def save_done(domain):
    with open(DONE_FILE, "a") as f:
        f.write(domain + "\n")


def write_emails(domain, emails, writer, fh):
    with write_lock:
        for email in emails:
            writer.writerow({"domain": domain, "email": email})
        fh.flush()


def main():
    with open(DOMAINS_FILE) as f:
        all_domains = [l.strip() for l in f if l.strip()]

    done = load_done()
    todo = [d for d in all_domains if d not in done]

    print(f"Total domains  : {len(all_domains)}")
    print(f"Already done   : {len(done)}")
    print(f"Remaining      : {len(todo)}")
    print(f"Workers        : {WORKERS}")
    print("="*55)

    # Check rate limit
    r = SESSION.get("https://api.github.com/rate_limit", timeout=10)
    if r.ok:
        rl = r.json()["resources"]
        print(f"Core API       : {rl['core']['remaining']}/{rl['core']['limit']} req remaining")
        print(f"Search API     : {rl['search']['remaining']}/{rl['search']['limit']} req remaining")
    print("="*55)

    found_total = 0
    processed = 0

    file_exists = os.path.exists(OUTPUT) and os.path.getsize(OUTPUT) > 10
    mode = "a" if file_exists else "w"

    with open(OUTPUT, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain", "email"])
        if not file_exists:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(harvest_domain, d): d for d in todo}
            for future in as_completed(futures):
                domain, emails = future.result()
                processed += 1
                save_done(domain)

                if emails:
                    write_emails(domain, emails, writer, fh)
                    found_total += len(emails)
                    print(f"[{processed:>4}/{len(todo)}] ✅ {domain:35s} +{len(emails)} → {found_total} total")
                else:
                    if processed % 20 == 0:
                        print(f"[{processed:>4}/{len(todo)}] ... {found_total} emails so far")

    print(f"\n{'='*55}")
    print(f"  DONE")
    print(f"  Domains processed : {processed}")
    print(f"  Emails found      : {found_total}")
    print(f"  Saved to          : {OUTPUT}")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
