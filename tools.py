"""
tools.py - The "tools" PhishHunter's agents can call.

In a real SOC these would call VirusTotal, WHOIS, Microsoft 365 / Google Workspace
admin APIs, Jira, etc.  For this Proof of Concept every tool reads/writes DUMMY data
from the data/ folder, so the whole system runs offline and safely.
"""
import json
import re
from difflib import SequenceMatcher
from pathlib import Path

DATA = Path(__file__).parent / "data"


def _load(name):
    with open(DATA / name, encoding="utf-8") as f:
        return json.load(f)


EMAILS = {e["id"]: e for e in _load("emails.json")}
INTEL = _load("threat_intel.json")
ORG = _load("org_context.json")


# ---------------------------------------------------------------- extraction tools
def get_email(email_id):
    return EMAILS[email_id]


def list_emails():
    return list(EMAILS.values())


def extract_urls(text):
    return re.findall(r"https?://[^\s\"'<>]+", text)


def domain_of(address_or_url):
    """'a@b.com' -> 'b.com',  'https://x.b.com/p' -> 'x.b.com'"""
    s = address_or_url.split("@")[-1]
    s = re.sub(r"^https?://", "", s)
    return s.split("/")[0].split("?")[0].lower()


def registered_domain(host):
    """'login-microsoft365.nimbus-tech-support.com' -> 'nimbus-tech-support.com'"""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---------------------------------------------------------------- threat-intel tools
def lookup_domain(domain):
    return INTEL["domains"].get(registered_domain(domain),
                                {"reputation": "unknown", "category": "not in feed", "age_days": None, "reports": 0})


def lookup_ip(ip):
    return INTEL["ips"].get(ip, {"reputation": "unknown", "abuse_score": 0, "country": "?", "note": "not in feed"})


def lookup_file_hash(sha256):
    return INTEL["file_hashes"].get(sha256, {"verdict": "unknown", "family": None, "detections": "0/72"})


def expand_short_link(url):
    """Simulates following a bit.ly redirect in a sandbox."""
    return INTEL["short_links"].get(url)


def lookalike_check(domain):
    """Is this domain pretending to be one of our protected brands?"""
    dom = registered_domain(domain)
    best = None
    for brand in ORG["protected_brands"]:
        if dom == brand:
            return None  # exact match = the real brand
        brand_word = brand.split(".")[0]
        similarity = SequenceMatcher(None, dom.split(".")[0].replace("-", ""), brand_word).ratio()
        contains = brand_word in dom.replace("-", "")
        if contains or similarity >= 0.75:
            score = max(similarity, 0.9 if contains else 0)
            if not best or score > best["similarity"]:
                best = {"impersonates": brand, "similarity": round(score, 2)}
    return best


# ---------------------------------------------------------------- org / mailbox tools
def find_campaign_recipients(sender, subject):
    """Search all mailboxes for other copies of the same email (blast radius)."""
    for row in ORG["delivery_log"]:
        if row["sender"] == sender and row["subject"] == subject:
            return row["recipients"]
    return []


def find_clicks(urls, attachments):
    """Who clicked the link / opened the attachment? (proxy + EDR logs)"""
    hits = []
    for c in ORG["click_log"]:
        for u in urls:
            if c["url"].split("?")[0] == u.split("?")[0]:
                hits.append(c)
        for a in attachments:
            if c["url"] == f"attachment:{a['filename']}":
                hits.append(c)
    unique = {(h["user"], h["url"]): h for h in hits}
    return list(unique.values())


# ---------------------------------------------------------------- response (action) tools
# These only RECORD what would happen. In production they would call the mail / IAM APIs.
def quarantine_messages(sender, subject, mailboxes):
    return f"Quarantined '{subject}' from {sender} in {len(mailboxes)} mailbox(es)"


def block_sender(domain_or_address):
    return f"Added {domain_or_address} to the email gateway blocklist"


def block_url(url):
    return f"Blocked {url} on the web proxy"


def force_password_reset(user):
    return f"Forced password reset + revoked sessions for {user}"


def isolate_endpoint(user):
    return f"Isolated laptop of {user} via EDR for malware scan"


def hold_payment(reference):
    return f"Placed finance hold on {reference} pending call-back verification"


_ticket_no = [1040]


def create_ticket(title, severity):
    _ticket_no[0] += 1
    return f"INC-{_ticket_no[0]}", f"Created ticket INC-{_ticket_no[0]} [{severity}] {title}"
