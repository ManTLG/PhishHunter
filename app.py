"""
PhishHunter - web demo.   Run with:   streamlit run app.py
"""
import os
import uuid

import pandas as pd
import streamlit as st

st.set_page_config(page_title="PhishHunter", page_icon="🎣", layout="wide")

# ---------------------------------------------------------------- sidebar: settings
with st.sidebar:
    st.title("🎣 PhishHunter")
    st.caption("Multi-agent phishing triage for a SOC team (PoC, dummy data)")
    key = st.text_input("Gemini API key (optional)", type="password",
                        help="Free key from aistudio.google.com. Leave empty to run in offline rule-based mode.")
    if key:
        os.environ["GOOGLE_API_KEY"] = key
    offline = st.toggle("Force offline mode", value=False)
    os.environ["PHISHHUNTER_OFFLINE"] = "1" if offline else "0"

import tools  # noqa: E402  (import after env vars are set)
from graph import resume_triage, start_triage  # noqa: E402
from llm import llm_available  # noqa: E402

with st.sidebar:
    if llm_available():
        st.success("LLM: Gemini connected")
    else:
        st.info("LLM: offline rule-based mode")
    st.divider()
    st.markdown("**Agents**\n1. Intake\n2. Header Forensics ∥\n3. Threat Intel ∥\n4. Content Analyst (LLM) ∥\n"
                "5. Risk Scoring\n6. Human Analyst (grey zone)\n7. Response\n8. Report (LLM)")

VERDICT_COLOR = {"MALICIOUS": "red", "SUSPICIOUS": "orange", "SAFE": "green"}
ss = st.session_state
ss.setdefault("results", {})     # email_id -> final state
ss.setdefault("pending", {})     # email_id -> (thread_id, question)

tab_triage, tab_dash = st.tabs(["🔍 Triage a reported email", "📊 SOC dashboard"])

# ---------------------------------------------------------------- tab 1: triage one email
with tab_triage:
    emails = tools.list_emails()
    labels = {e["id"]: f"{e['id']} · {e['subject']}" for e in emails}
    eid = st.selectbox("Phishing-report inbox", list(labels), format_func=labels.get)
    e = tools.get_email(eid)

    left, right = st.columns([1, 1.25], gap="large")
    with left:
        st.subheader("Reported email")
        with st.container(border=True):
            st.markdown(f"**From:** {e['from_name']} &lt;{e['from_address']}&gt;  \n"
                        f"**To:** {e['to']}  \n**Subject:** {e['subject']}  \n"
                        f"**Reported by:** {e['reported_by']} · {e['received_at']}")
            st.text(e["body"])
            for a in e["attachments"]:
                st.markdown(f"📎 `{a['filename']}` ({a['size_kb']} KB)")
        run = st.button("🚀 Run PhishHunter", type="primary", width="stretch")

    if run:
        thread = str(uuid.uuid4())
        with st.spinner("Agents are investigating..."):
            state, pending = start_triage(eid, thread)
        ss.results[eid] = state
        if pending:
            ss.pending[eid] = (thread, pending)
        else:
            ss.pending.pop(eid, None)

    with right:
        state = ss.results.get(eid)
        if not state:
            st.info("Pick an email and press **Run PhishHunter** to watch the agents work.")
        else:
            st.subheader("Agent trace")
            for step in state["trace"]:
                st.markdown(f"**{step['agent']}** — {step['message']}")

            score = state["risk_score"]
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk score", f"{score}/100")
            c2.markdown(f"**Verdict**  \n:{VERDICT_COLOR[state['verdict']]}[**{state['verdict']}**]")
            c3.markdown(f"**Threat**  \n{state['threat_type']}")
            st.progress(score / 100)

            if state["signals"]:
                with st.expander(f"Evidence ({len(state['signals'])} signals)", expanded=True):
                    st.dataframe(pd.DataFrame(state["signals"])[["agent", "signal", "points", "detail"]],
                                 hide_index=True, width="stretch")

            if eid in ss.pending:
                thread, q = ss.pending[eid]
                st.warning(f"🧑‍💻 **Human review needed** — score {q['score']} is in the grey zone (40–79). "
                           "PhishHunter will not act on its own here.")
                b1, b2 = st.columns(2)
                decision = None
                if b1.button("Confirm MALICIOUS", type="primary", width="stretch"):
                    decision = "malicious"
                if b2.button("Mark SAFE", width="stretch"):
                    decision = "safe"
                if decision:
                    with st.spinner("Resuming workflow..."):
                        state, _ = resume_triage(decision, thread)
                    ss.results[eid] = state
                    ss.pending.pop(eid)
                    st.rerun()
            else:
                if state.get("actions"):
                    st.subheader(f"Containment · {state['ticket']} · severity {state['severity']}")
                    st.caption(f"Reached {len(state['blast_radius'])} mailbox(es); "
                               f"{len(state['clicks'])} user(s) interacted")
                    for a in state["actions"]:
                        st.markdown(f"✅ {a}")
                st.subheader("Incident report")
                st.caption(f"Decided by: {state['decided_by']}")
                st.write(state["report"])
                st.markdown("**Reply sent to the reporter**")
                st.success(state["reporter_reply"])

# ---------------------------------------------------------------- tab 2: dashboard
with tab_dash:
    st.subheader("Process the whole inbox")
    st.caption("Grey-zone emails stay in the analyst queue instead of being auto-actioned.")
    if st.button("Triage all reported emails"):
        bar = st.progress(0.0)
        for n, em in enumerate(tools.list_emails(), 1):
            thread = str(uuid.uuid4())
            state, pending = start_triage(em["id"], thread)
            ss.results[em["id"]] = state
            if pending:
                ss.pending[em["id"]] = (thread, pending)
            bar.progress(n / len(tools.list_emails()))
    if ss.results:
        rows = []
        for eid_, s in sorted(ss.results.items()):
            rows.append({"Email": eid_, "Subject": s["email"]["subject"], "Score": s["risk_score"],
                         "Verdict": "AWAITING ANALYST" if eid_ in ss.pending else s["verdict"],
                         "Threat": s["threat_type"], "Mailboxes": len(s.get("blast_radius", [])),
                         "Actions": len(s.get("actions", [])), "Ticket": s.get("ticket", "-")})
        df = pd.DataFrame(rows)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Reports triaged", len(df))
        m2.metric("Auto-contained", int((df.Verdict == "MALICIOUS").sum()))
        m3.metric("Awaiting analyst", int((df.Verdict == "AWAITING ANALYST").sum()))
        m4.metric("Closed as safe", int((df.Verdict == "SAFE").sum()))
        st.dataframe(df, hide_index=True, width="stretch")
