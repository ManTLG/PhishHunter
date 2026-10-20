"""
Run PhishHunter from the terminal.

    python run_cli.py            # triage all 7 sample emails
    python run_cli.py E5         # triage one email (asks you to decide if it is grey-zone)
    python run_cli.py --auto     # all emails, grey-zone ones auto-answered "malicious"
"""
import sys
import uuid

from graph import llm_available, resume_triage, start_triage
import tools


def show(state):
    print(f"\n  Verdict : {state['verdict']}  (score {state['risk_score']}/100, decided by {state['decided_by']})")
    print(f"  Threat  : {state['threat_type']}")
    for a in state.get("actions", []):
        print(f"  ACTION  : {a}")
    print(f"  Report  : {state['report']}")
    print(f"  Reply   : {state['reporter_reply']}")


def triage(email_id, auto):
    e = tools.get_email(email_id)
    print("=" * 90)
    print(f"[{email_id}] {e['subject']}   <{e['from_address']}>")
    thread = str(uuid.uuid4())
    state, pending = start_triage(email_id, thread)
    for step in state["trace"]:
        print(f"  - {step['agent']:<24} {step['message']}")
    if pending:
        print(f"\n  >> HUMAN REVIEW NEEDED (score {pending['score']}):")
        for ev in pending["evidence"]:
            print(f"       * {ev}")
        answer = "malicious" if auto else input("     Your decision [malicious/safe]: ").strip() or "malicious"
        state, _ = resume_triage(answer, thread)
        for step in state["trace"][-3:]:
            print(f"  - {step['agent']:<24} {step['message']}")
    show(state)


if __name__ == "__main__":
    print(f"PhishHunter - LLM mode: {'Gemini' if llm_available() else 'OFFLINE (rule-based)'}")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ids = args or [e["id"] for e in tools.list_emails()]
    for i in ids:
        triage(i, auto="--auto" in sys.argv)
