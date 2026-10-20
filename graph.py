"""
graph.py - PhishHunter multi-agent workflow built with LangGraph.

                         +--> Header Forensics Agent --+
  Intake Agent ----------+--> Threat Intel Agent ------+--> Risk Scoring Agent --> (router)
                         +--> Content Analyst Agent ---+
        router:  score >= 80  -> Response Agent -> Report Agent
                 40..79       -> Human Analyst Review -> Response Agent or Report Agent
                 < 40         -> Report Agent (close as safe)
"""
import json
import operator
import re
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

import tools
from llm import ask, ask_json, llm_available

MALICIOUS_AT = 80
SUSPICIOUS_AT = 40


# ======================================================================= shared state
class TriageState(TypedDict, total=False):
    email_id: str
    email: dict
    iocs: dict                                   # indicators extracted by Intake
    signals: Annotated[list, operator.add]       # evidence from the 3 parallel agents
    trace: Annotated[list, operator.add]         # step-by-step log shown in the UI
    content: dict                                # Content Analyst's reading of the email
    risk_score: int
    verdict: str                                 # MALICIOUS / SUSPICIOUS / SAFE
    threat_type: str
    decided_by: str                              # "PhishHunter (auto)" or "Human analyst"
    blast_radius: list
    clicks: list
    actions: list
    ticket: str
    severity: str
    report: str
    reporter_reply: str


def log(agent, msg):
    return [{"agent": agent, "message": msg}]


def signal(agent, name, points, detail):
    return {"agent": agent, "signal": name, "points": points, "detail": detail}


# ======================================================================= 1. Intake Agent
def intake_agent(state: TriageState):
    email = tools.get_email(state["email_id"])
    urls = tools.extract_urls(email["body"])
    expanded = {}
    for u in urls:
        final = tools.expand_short_link(u)
        if final:
            expanded[u] = final
    iocs = {
        "sender_domain": tools.domain_of(email["from_address"]),
        "reply_to_domain": tools.domain_of(email["reply_to"]),
        "urls": urls,
        "expanded_urls": expanded,
        "url_domains": sorted({tools.domain_of(u) for u in urls + list(expanded.values())}),
        "attachments": email["attachments"],
        "sender_ip": email["sender_ip"],
    }
    msg = (f"Parsed report from {email['reported_by']}: {len(urls)} URL(s), "
           f"{len(email['attachments'])} attachment(s)")
    if expanded:
        msg += f"; expanded short link -> {list(expanded.values())[0]}"
    return {"email": email, "iocs": iocs, "trace": log("Intake Agent", msg)}


# ======================================================================= 2. Header Forensics Agent
def header_agent(state: TriageState):
    e, i = state["email"], state["iocs"]
    org, sigs = tools.ORG, []
    auth = e["auth"]
    if auth["spf"] == "fail":
        sigs.append(signal("Header", "SPF failed", 15, "Sending server not authorised for this domain"))
    elif auth["spf"] == "softfail":
        sigs.append(signal("Header", "SPF softfail", 8, "Sender authentication weak"))
    if auth["dmarc"] == "fail":
        sigs.append(signal("Header", "DMARC failed", 10, "Domain owner policy rejects this message"))
    if i["reply_to_domain"] != i["sender_domain"]:
        sigs.append(signal("Header", "Reply-To mismatch", 10, f"Replies go to {i['reply_to_domain']}"))

    external = i["sender_domain"] != org["internal_domain"]
    exec_named = [x for x in org["executives"] if x.lower() in e["from_name"].lower()]
    if external and exec_named:
        sigs.append(signal("Header", "Executive impersonation", 30,
                           f"Display name '{e['from_name']}' but sent from external {i['sender_domain']}"))
        if tools.lookup_domain(i["sender_domain"]).get("category") == "free webmail":
            sigs.append(signal("Header", "Free webmail sender", 5, "Executives never use personal Gmail"))
    elif external and re.search(r"\b(nimbus|it helpdesk|hr|payroll)\b", e["from_name"], re.I):
        sigs.append(signal("Header", "Internal team impersonation", 15,
                           f"'{e['from_name']}' claims to be internal but domain is {i['sender_domain']}"))

    look = tools.lookalike_check(i["sender_domain"])
    if look:
        vendor = look["impersonates"] in org["known_vendors"].values()
        sigs.append(signal("Header", "Look-alike domain", 20 if vendor else 25,
                           f"{i['sender_domain']} imitates {look['impersonates']} (similarity {look['similarity']})"))

    msg = f"SPF={auth['spf']} DKIM={auth['dkim']} DMARC={auth['dmarc']}; {len(sigs)} red flag(s)"
    return {"signals": sigs, "trace": log("Header Forensics Agent", msg)}


# ======================================================================= 3. Threat Intel Agent
def intel_agent(state: TriageState):
    i, sigs = state["iocs"], []
    domains = sorted({i["sender_domain"], *i["url_domains"]})
    youngest = None
    for d in domains:
        rep = tools.lookup_domain(d)
        if rep["reputation"] == "malicious":
            sigs.append(signal("Intel", "Malicious domain", 35, f"{d}: {rep['category']} ({rep['reports']} reports)"))
        elif rep["reputation"] == "suspicious":
            sigs.append(signal("Intel", "Suspicious domain", 15, f"{d}: {rep['category']}"))
        if rep.get("age_days") is not None and rep["age_days"] < 30:
            if youngest is None or rep["age_days"] < youngest[1]:
                youngest = (d, rep["age_days"])
    if youngest:
        sigs.append(signal("Intel", "Newly registered domain", 15, f"{youngest[0]} is only {youngest[1]} days old"))

    ip = tools.lookup_ip(i["sender_ip"])
    if ip["reputation"] == "malicious":
        sigs.append(signal("Intel", "Malicious sender IP", 15, f"{i['sender_ip']} abuse score {ip['abuse_score']} - {ip['note']}"))

    if i["expanded_urls"]:
        sigs.append(signal("Intel", "URL shortener", 5, "Link hides its real destination"))

    for a in i["attachments"]:
        h = tools.lookup_file_hash(a["sha256"])
        if h["verdict"] == "malicious":
            sigs.append(signal("Intel", "Malware attachment", 50, f"{a['filename']}: {h['family']} ({h['detections']} engines)"))
        if re.search(r"\.(pdf|doc|docx|xls|jpg)\.(exe|scr|js|vbs|bat)$", a["filename"], re.I):
            sigs.append(signal("Intel", "Disguised executable", 25, f"{a['filename']} uses a double extension"))

    msg = f"Checked {len(domains)} domain(s), 1 IP, {len(i['attachments'])} file hash(es); {len(sigs)} hit(s)"
    return {"signals": sigs, "trace": log("Threat Intel Agent", msg)}


# ======================================================================= 4. Content Analyst Agent (LLM)
TACTIC_POINTS = {
    "credential_request": 20, "gift_card_request": 25, "bank_detail_change": 20,
    "payment_request": 10, "urgency": 10, "threat_of_loss": 10, "secrecy": 10,
}
TACTIC_LABELS = {
    "credential_request": "Asks for login / password", "gift_card_request": "Gift-card request",
    "bank_detail_change": "Bank-detail change request", "payment_request": "Asks for payment",
    "urgency": "Artificial urgency", "threat_of_loss": "Threat of account loss / penalty",
    "secrecy": "Asks to keep it secret",
}

CONTENT_PROMPT = """You are the Content Analyst agent in a corporate phishing-triage team.
Read the reported email and identify social-engineering tactics. Only flag a tactic if the
email clearly uses it. Normal newsletters and notifications should have no tactics.

Allowed tactics: credential_request, gift_card_request, bank_detail_change, payment_request,
urgency, threat_of_loss, secrecy.
Allowed intents: credential_phishing, business_email_compromise, invoice_or_payment_fraud,
malware_delivery, scam, legitimate.

Email:
From: {from_name} <{from_address}>
Subject: {subject}
Attachments: {attachments}
Body:
{body}

Return JSON: {{"intent": "...", "tactics": ["..."], "summary": "one sentence plain-English summary of what the email wants the reader to do"}}"""


def _offline_content(e):
    """Keyword rules used when no LLM is available."""
    t = (e["subject"] + " " + e["body"]).lower()
    rules = {
        "credential_request": r"verify your account|password|login|sign in",
        "gift_card_request": r"gift card",
        "bank_detail_change": r"bank details|banking partner|new account",
        "payment_request": r"payment|pay now|fee|purchase|process the payment|reimburse",
        "urgency": r"immediately|within (the next )?\d+|today|in \d+ hours|action required|are you at your desk",
        "threat_of_loss": r"suspension|suspended|returned to sender|late fee|lose access|losing access",
        "secrecy": r"confidential|keep this|surprise",
    }
    tactics = [k for k, rx in rules.items() if re.search(rx, t)]
    if "password" in t and "expire" in t:
        intent = "credential_phishing"
    elif "gift card" in t:
        intent = "business_email_compromise"
    elif "bank details" in t or "invoice" in t:
        intent = "invoice_or_payment_fraud"
    elif "parcel" in t:
        intent = "scam"
    else:
        intent, tactics = "legitimate", []
    return {"intent": intent, "tactics": tactics,
            "summary": f"Email titled '{e['subject']}' ({intent.replace('_', ' ')}).", "engine": "offline rules"}


def content_agent(state: TriageState):
    e = state["email"]
    prompt = CONTENT_PROMPT.format(from_name=e["from_name"], from_address=e["from_address"],
                                   subject=e["subject"], body=e["body"],
                                   attachments=[a["filename"] for a in e["attachments"]] or "none")
    result = ask_json(prompt)
    if result and "tactics" in result:
        result["engine"] = "Gemini"
        result["tactics"] = [t for t in result["tactics"] if t in TACTIC_POINTS]
    else:
        result = _offline_content(e)
    sigs = [signal("Content", TACTIC_LABELS[t], TACTIC_POINTS[t], "Social-engineering tactic in text")
            for t in result["tactics"]]
    msg = f"[{result['engine']}] intent={result['intent']}; tactics={', '.join(result['tactics']) or 'none'}"
    return {"content": result, "signals": sigs, "trace": log("Content Analyst Agent", msg)}


# ======================================================================= 5. Risk Scoring Agent
def risk_agent(state: TriageState):
    score = min(100, sum(s["points"] for s in state["signals"]))
    if score >= MALICIOUS_AT:
        verdict = "MALICIOUS"
    elif score >= SUSPICIOUS_AT:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    names = {s["signal"] for s in state["signals"]}
    intent = state["content"]["intent"]
    if "Malware attachment" in names or "Disguised executable" in names:
        threat = "Malware delivery"
    elif intent == "legitimate" and verdict == "SAFE":
        threat = "None (legitimate email)"
    else:
        threat = intent.replace("_", " ").capitalize()
    route = {"MALICIOUS": "auto-respond", "SUSPICIOUS": "send to human analyst", "SAFE": "close"}[verdict]
    return {"risk_score": score, "verdict": verdict, "threat_type": threat,
            "decided_by": "PhishHunter (auto)",
            "trace": log("Risk Scoring Agent", f"Score {score}/100 -> {verdict} ({threat}); next: {route}")}


def route_after_scoring(state: TriageState):
    return {"MALICIOUS": "response_agent", "SUSPICIOUS": "human_review", "SAFE": "report_agent"}[state["verdict"]]


# ======================================================================= 6. Human-in-the-loop
def human_review(state: TriageState):
    # LangGraph pauses here and waits for an analyst decision ("malicious" / "safe").
    decision = interrupt({
        "question": "Grey-zone email. Analyst, is this malicious?",
        "score": state["risk_score"],
        "evidence": [f"{s['signal']}: {s['detail']}" for s in state["signals"]],
    })
    verdict = "MALICIOUS" if str(decision).lower().startswith("mal") else "SAFE"
    return {"verdict": verdict, "decided_by": "Human analyst",
            "trace": log("Human Analyst", f"Reviewed evidence and marked the email {verdict}")}


def route_after_review(state: TriageState):
    return "response_agent" if state["verdict"] == "MALICIOUS" else "report_agent"


# ======================================================================= 7. Response Agent
def response_agent(state: TriageState):
    e, i = state["email"], state["iocs"]
    actions = []
    recipients = tools.find_campaign_recipients(e["from_address"], e["subject"]) or [e["to"]]
    final_urls = list(i["expanded_urls"].values()) or i["urls"]
    clicks = tools.find_clicks(i["urls"] + final_urls, i["attachments"])

    actions.append(tools.quarantine_messages(e["from_address"], e["subject"], recipients))
    if tools.lookup_domain(i["sender_domain"]).get("category") == "free webmail":
        actions.append(tools.block_sender(e["from_address"]))   # never block all of gmail.com
    else:
        actions.append(tools.block_sender(i["sender_domain"]))
    for u in final_urls:
        if tools.lookup_domain(tools.domain_of(u))["reputation"] in ("malicious", "suspicious"):
            actions.append(tools.block_url(u.split("?")[0]))

    compromised = False
    for c in clicks:
        if c["url"].startswith("attachment:"):
            actions.append(tools.isolate_endpoint(c["user"]))
            compromised = True
        elif c["credentials_submitted"] and "pay" in c["url"] + "".join(final_urls):
            actions.append(f"Called {c['user']} to block the payment card entered on the scam page")
            compromised = True
        elif c["credentials_submitted"]:
            actions.append(tools.force_password_reset(c["user"]))
            compromised = True
        else:
            actions.append(f"Flagged {c['user']} for monitoring (clicked, no credentials entered)")

    threat = state["threat_type"].lower()
    if "business email" in threat or "payment" in threat or "invoice" in threat:
        po = re.findall(r"PO-\d+|#\d+", e["body"])
        actions.append(tools.hold_payment(po[0] if po else "any payment requested by this sender"))
        actions.append("Alerted Finance team to call the vendor/executive on a known phone number")

    severity = "HIGH" if compromised else "MEDIUM"
    ticket_id, ticket_msg = tools.create_ticket(f"{state['threat_type']} - {e['subject'][:50]}", severity)
    actions.append(ticket_msg)

    msg = (f"Blast radius: {len(recipients)} mailbox(es), {len(clicks)} click(s); "
           f"executed {len(actions)} containment action(s); severity {severity}")
    return {"blast_radius": recipients, "clicks": clicks, "actions": actions, "ticket": ticket_id,
            "severity": severity, "trace": log("Response Agent", msg)}


# ======================================================================= 8. Report Agent (LLM)
REPORT_PROMPT = """You are the Report agent of PhishHunter, an AI phishing-triage system.
Write a short incident summary for the security team (max 120 words, plain text, no markdown
headings) and then a friendly 2-3 sentence reply to the employee who reported the email.

Case data (JSON):
{case}

Return JSON: {{"report": "...", "reporter_reply": "..."}}"""


def _offline_report(s):
    e = s["email"]
    top = sorted(s["signals"], key=lambda x: -x["points"])[:4]
    why = "; ".join(f"{x['signal']} ({x['detail']})" for x in top) or "no red flags found"
    if s["verdict"] == "MALICIOUS":
        report = (f"{s['threat_type']} email '{e['subject']}' from {e['from_address']} scored "
                  f"{s['risk_score']}/100 and was confirmed MALICIOUS by {s['decided_by']}. Key evidence: {why}. "
                  f"It reached {len(s.get('blast_radius', []))} mailbox(es) and {len(s.get('clicks', []))} user(s) interacted. "
                  f"{len(s.get('actions', []))} containment actions were taken under {s.get('ticket')} (severity {s.get('severity')}).")
        reply = (f"Thank you for reporting this, it was a real {s['threat_type'].lower()} attempt. "
                 "We have removed it from all inboxes and blocked the sender. Please do not interact with similar emails.")
    else:
        report = (f"Email '{e['subject']}' from {e['from_address']} scored {s['risk_score']}/100 and was "
                  f"marked SAFE by {s['decided_by']}. Evidence reviewed: {why}. No action required.")
        reply = ("Thanks for staying alert and reporting this. We checked it and it is a legitimate email, "
                 "so it is safe to use. Keep reporting anything that looks unusual!")
    return report, reply


def report_agent(state: TriageState):
    case = {k: state.get(k) for k in ("verdict", "risk_score", "threat_type", "decided_by", "severity", "ticket", "actions")}
    case["email"] = {k: state["email"][k] for k in ("from_name", "from_address", "subject", "reported_by")}
    case["evidence"] = [f"{s['signal']}: {s['detail']}" for s in state["signals"]]
    case["mailboxes_affected"] = len(state.get("blast_radius", []))
    case["users_who_clicked"] = [c["user"] for c in state.get("clicks", [])]
    out = ask_json(REPORT_PROMPT.format(case=json.dumps(case, indent=1)))
    if out and "report" in out:
        report, reply, engine = out["report"], out.get("reporter_reply", ""), "Gemini"
    else:
        (report, reply), engine = _offline_report(state), "offline template"
    return {"report": report, "reporter_reply": reply,
            "trace": log("Report Agent", f"[{engine}] Incident summary written and reply sent to {state['email']['reported_by']}")}


# ======================================================================= build the graph
def build_graph():
    g = StateGraph(TriageState)
    g.add_node("intake_agent", intake_agent)
    g.add_node("header_agent", header_agent)
    g.add_node("intel_agent", intel_agent)
    g.add_node("content_agent", content_agent)
    g.add_node("risk_agent", risk_agent)
    g.add_node("human_review", human_review)
    g.add_node("response_agent", response_agent)
    g.add_node("report_agent", report_agent)

    g.add_edge(START, "intake_agent")
    for analyst in ("header_agent", "intel_agent", "content_agent"):   # run in parallel
        g.add_edge("intake_agent", analyst)
    g.add_edge(["header_agent", "intel_agent", "content_agent"], "risk_agent")
    g.add_conditional_edges("risk_agent", route_after_scoring,
                            ["response_agent", "human_review", "report_agent"])
    g.add_conditional_edges("human_review", route_after_review, ["response_agent", "report_agent"])
    g.add_edge("response_agent", "report_agent")
    g.add_edge("report_agent", END)
    return g.compile(checkpointer=MemorySaver())


GRAPH = build_graph()


def start_triage(email_id, thread_id):
    """Run until finished or until the human-review pause. Returns (state, pending_question)."""
    cfg = {"configurable": {"thread_id": thread_id}}
    GRAPH.invoke({"email_id": email_id, "signals": [], "trace": []}, cfg)
    return _status(cfg)


def resume_triage(decision, thread_id):
    cfg = {"configurable": {"thread_id": thread_id}}
    GRAPH.invoke(Command(resume=decision), cfg)
    return _status(cfg)


def _status(cfg):
    snap = GRAPH.get_state(cfg)
    pending = None
    for task in snap.tasks:
        if task.interrupts:
            pending = task.interrupts[0].value
    return snap.values, pending


__all__ = ["GRAPH", "start_triage", "resume_triage", "llm_available"]
