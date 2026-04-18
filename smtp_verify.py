#!/usr/bin/env python3
"""
SMTP Email Verifier — vérifie si un email existe sans l'envoyer
Technique: RCPT TO check sur le serveur MX du domaine
"""

import dns.resolver
import smtplib
import csv
import time
import re
import itertools

# ── Config ─────────────────────────────────────────────────────────────────────
FROM_EMAIL = "verify@gmail.com"   # adresse fictive d'expéditeur
TIMEOUT    = 6                    # secondes par connexion
DELAY      = 1.0                  # entre chaque vérification


def get_mx(domain):
    """Retourne le serveur MX du domaine."""
    try:
        records = dns.resolver.resolve(domain, "MX")
        return str(sorted(records, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return None


def smtp_check(email, mx_host):
    """
    Retourne True si le serveur MX accepte l'email (RCPT TO: 250/251).
    False si rejeté (550/553). None si inconclusif (catch-all ou erreur).
    """
    domain = email.split("@")[1]
    try:
        with smtplib.SMTP(mx_host, 25, timeout=TIMEOUT) as smtp:
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(FROM_EMAIL)
            code, msg = smtp.rcpt(email)
            if code in (250, 251):
                # Check if it's a catch-all (accepts everything)
                fake = f"zzz_fake_xyz_999@{domain}"
                smtp.mail(FROM_EMAIL)
                code2, _ = smtp.rcpt(fake)
                if code2 in (250, 251):
                    return None  # catch-all — inconclusive
                return True
            elif code in (550, 551, 553, 554):
                return False
            return None
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
            ConnectionRefusedError, OSError, TimeoutError):
        return None
    except Exception:
        return None


def generate_patterns(first, last, domain):
    """Génère des variations d'emails à partir d'un prénom/nom."""
    f = first.lower()
    l = last.lower()
    fi = f[0] if f else ""
    li = l[0] if l else ""
    patterns = []
    if f:   patterns.append(f"{f}@{domain}")
    if f and l:
        patterns += [
            f"{f}.{l}@{domain}",
            f"{f}{l}@{domain}",
            f"{fi}{l}@{domain}",
            f"{fi}.{l}@{domain}",
            f"{f}_{l}@{domain}",
            f"{f}-{l}@{domain}",
            f"{f}{li}@{domain}",
        ]
    return patterns


def verify_domain_emails(domain, names):
    """
    Prend un domaine + liste de (prenom, nom) et retourne les emails vérifiés.
    """
    mx = get_mx(domain)
    if not mx:
        print(f"  [{domain}] Pas de MX")
        return []

    results = []
    checked = set()

    for first, last in names:
        for email in generate_patterns(first, last, domain):
            if email in checked:
                continue
            checked.add(email)
            result = smtp_check(email, mx)
            time.sleep(0.3)
            if result is True:
                print(f"  ✅ VALID: {email}")
                results.append(email)
                break   # On a trouvé le bon format, inutile de continuer
            elif result is False:
                pass    # email inexistant
            else:
                pass    # inconclusive

    return results


# ── Liste des entreprises avec noms connus ─────────────────────────────────────
# Format: (domaine, [(prenom, nom), ...])
# Noms tirés de GitHub commits + recherches publiques

TARGETS = [
    # Depuis nos résultats GitHub
    ("e2b.dev",            [("Jakub", "Novak"), ("Tereza", "Tizkova")]),
    ("vapi.ai",            [("Dhruva", "Reddy"), ("Jordan", "Dearsley")]),
    ("firecrawl.dev",      [("Nicolas", "Camara"), ("Felipe", "Gama")]),
    ("letta.com",          [("Charles", "Packer"), ("Sarah", "Wooders")]),
    ("crewai.com",         [("Joao", "Moura"), ("Vinicius", "Godoy")]),
    ("dust.tt",            [("Thomas", "Draier"), ("Stanislas", "Polu")]),
    ("modal.com",          [("Erik", "Bernhardsson"), ("Charles", "Frye")]),
    ("browserbase.com",    [("Shrey", "Pandya"), ("Paul", "Klein")]),
    ("recall.ai",          [("Nicholas", "Amello"), ("Dave", "Pereira")]),
    ("relevanceai.com",    [("Alex", "Waite"), ("Daniel", "Vassilev")]),
    ("composio.dev",       [("Soham", "Ganguly"), ("Karan", "Vaidya")]),
    ("humanloop.com",      [("Raza", "Habib"), ("Peter", "Hayes")]),
    ("superagi.com",       [("Mukunda", "Reddy"), ("Ishaan", "Bhola")]),
    ("flowise.ai",         [("Henry", "Heng"), ("Zi", "Wei")]),
    ("plandex.ai",         [("Dane", "Bouchie"), ("Chris", "Weaver")]),
    ("mem0.ai",            [("Taranjeet", "Singh"), ("Soumil", "Rathi")]),
    ("agno.com",           [("Ashpreet", "Bedi"), ("Sid", "Bharath")]),
    ("cognition.ai",       [("Scott", "Wu"), ("Steven", "Hao")]),
    ("gumloop.com",        [("Max", "Brodeur"), ("Sam", "Gutkin")]),
    ("wordware.ai",        [("Filip", "Kozera"), ("Robert", "Chandler")]),
    ("bland.ai",           [("Isaiah", "Granet"), ("Sobhan", "Tehrani")]),
    ("lindy.ai",           [("Flo", "Crivello"), ("Felix", "Bast")]),
    ("induced.ai",         [("Aryan", "Sharma"), ("Pranjal", "Singh")]),
    ("windsurf.com",       [("Varun", "Mohan"), ("Douglas", "Chen")]),
    ("cassidyai.com",      [("Cassidy", "Williams"), ("Perry", "Metzger")]),
    ("cognition.ai",       [("Scott", "Wu"), ("Walden", "Yan")]),
]

def main():
    output = "smtp_verified_emails.csv"
    results = []

    print("="*60)
    print(" SMTP EMAIL VERIFIER — vérification sans envoi")
    print("="*60)

    for domain, names in TARGETS:
        print(f"\n[{domain}]")
        verified = verify_domain_emails(domain, names)
        time.sleep(DELAY)

        if verified:
            for email in verified:
                results.append({"domain": domain, "email": email, "method": "smtp_verified"})
        else:
            print(f"  → aucun email vérifié")
            results.append({"domain": domain, "email": "", "method": "not_found"})

    # Écrire CSV
    with open(output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["domain","email","method"])
        w.writeheader()
        w.writerows(results)

    found = [r for r in results if r["email"]]
    print(f"\n{'='*60}")
    print(f"  Emails SMTP vérifiés : {len(found)}/{len(TARGETS)}")
    print(f"  Sauvegardé dans      : {output}")
    print(f"{'='*60}")
    for r in found:
        print(f"  {r['domain']:25s}  {r['email']}")

if __name__ == "__main__":
    main()
