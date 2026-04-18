#!/usr/bin/env python3
"""
Mass email harvester — theHarvester github-code sur N domaines en parallèle
Ecrit les résultats progressivement dans mass_emails.csv
"""
import subprocess, csv, re, time, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

OUTPUT = "/Users/kokabuildsf/Scrapper/mass_emails.csv"
DOMAINS_FILE = "/Users/kokabuildsf/Scrapper/domains_quality.txt"
DONE_FILE = "/Users/kokabuildsf/Scrapper/domains_done.txt"
WORKERS = 6       # parallèle — github search rate limit ~30 req/min
LIMIT = 300       # résultats par domaine
GENERIC = {
    "support","hello","info","contact","team","press","privacy","legal",
    "security","hr","jobs","careers","noreply","no-reply","billing","sales",
    "help","admin","founders","founder","server","sandbox","demo","devops",
    "dev","devs","bot","guest","test1","test2","local-admin","feedback",
    "flow","booster","from-quick-form","neuralgpt_agent","dockerfile",
    "domains","soporte","guestuser","psl","ai","notify","notifications",
    "alerts","webhook","ops","infra","engineering","product","design",
    "marketing","finance","accounting","payroll","invoice","invoicing",
}

write_lock = Lock()

EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")


def is_personal(email, domain):
    if not email or "@" not in email:
        return False
    email = email.strip().lstrip("'\"")
    if " " in email or "," in email:
        return False
    local = email.split("@")[0].lower()
    dom = email.split("@")[1].lower()
    if domain not in dom:
        return False
    if local in GENERIC:
        return False
    if local.isdigit():
        return False
    if "Mac.localdomain" in email or "localdomain" in email:
        return False
    if len(local) < 2 or len(local) > 30:
        return False
    return True


def harvest_domain(domain):
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "github-code", "-l", str(LIMIT)],
            capture_output=True, text=True, timeout=45
        )
        output = result.stdout + result.stderr
        emails = EMAIL_RE.findall(output)
        personal = list({e.strip().lstrip("'\"") for e in emails if is_personal(e, domain)})
        return domain, personal
    except subprocess.TimeoutExpired:
        return domain, []
    except Exception:
        return domain, []


def load_done():
    done = set()
    if os.path.exists(DONE_FILE):
        with open(DONE_FILE) as f:
            done = {line.strip() for line in f}
    return done


def save_done(domain):
    with open(DONE_FILE, "a") as f:
        f.write(domain + "\n")


def write_emails(domain, emails, writer):
    with write_lock:
        for email in emails:
            writer.writerow({"domain": domain, "email": email})


def main():
    # Charger domaines
    with open(DOMAINS_FILE) as f:
        all_domains = [l.strip() for l in f if l.strip()]

    done = load_done()
    todo = [d for d in all_domains if d not in done]

    print(f"Total domaines: {len(all_domains)}")
    print(f"Déjà traités  : {len(done)}")
    print(f"Restants      : {len(todo)}")
    print(f"Workers       : {WORKERS}")
    print(f"Output        : {OUTPUT}")
    print("="*55)

    found_total = 0
    processed = 0

    # Mode append — reprend si interrompu
    file_exists = os.path.exists(OUTPUT)
    mode = "a" if file_exists else "w"

    with open(OUTPUT, mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain","email"])
        if not file_exists:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(harvest_domain, d): d for d in todo}
            for future in as_completed(futures):
                domain, emails = future.result()
                processed += 1
                save_done(domain)

                if emails:
                    write_emails(domain, emails, writer)
                    f.flush()
                    found_total += len(emails)
                    print(f"[{processed:>5}/{len(todo)}] ✅ {domain:35s} +{len(emails)} ({found_total} total)")
                else:
                    if processed % 50 == 0:
                        print(f"[{processed:>5}/{len(todo)}] ... {found_total} emails trouvés jusqu'ici")

    print(f"\n{'='*55}")
    print(f"  TERMINÉ")
    print(f"  Domaines traités : {processed}")
    print(f"  Emails trouvés   : {found_total}")
    print(f"  Sauvé dans       : {OUTPUT}")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
