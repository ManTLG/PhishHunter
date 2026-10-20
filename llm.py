"""
llm.py - One place that talks to the LLM.

Uses Google Gemini (free API key from https://aistudio.google.com) through LangChain.
If there is no key, or the call fails (no internet, quota hit), the agents fall back to
rule-based "offline mode" so the demo never breaks during a presentation.
"""
import json
import os
import re

MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
_llm = None


def llm_available():
    return bool(os.getenv("GOOGLE_API_KEY")) and os.getenv("PHISHHUNTER_OFFLINE") != "1"


def _get_llm():
    global _llm
    if _llm is None:
        from langchain_google_genai import ChatGoogleGenerativeAI
        _llm = ChatGoogleGenerativeAI(model=MODEL, temperature=0, max_retries=1, timeout=30)
    return _llm


def ask(prompt):
    """Return the model's text answer, or None if the LLM is not available."""
    if not llm_available():
        return None
    try:
        out = _get_llm().invoke(prompt).content
        if isinstance(out, list):  # some Gemini versions return content parts
            out = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in out)
        return out
    except Exception as e:  # network / quota / bad key -> offline fallback
        print(f"[llm] Gemini call failed, using offline mode: {e}")
        return None


def ask_json(prompt):
    """Ask for JSON and parse it. Returns dict or None."""
    text = ask(prompt + "\n\nRespond with ONLY valid JSON, no markdown fences.")
    if not text:
        return None
    match = re.search(r"\{.*\}", text, re.S)
    try:
        return json.loads(match.group(0)) if match else None
    except json.JSONDecodeError:
        return None
