"""PromptFence — Neomorphic & Spatial AI Agent Security Console.

A premium security console providing real-time prompt injection inspection,
verified offline-first benchmark analytics, interactive attack demonstrations,
and defense-in-depth architectural insights.

Integrates directly with PromptFence FastAPI backend and local Gemma 4 E2B via Ollama.
"""

from __future__ import annotations

import streamlit as st

from app.dashboard_helpers import (
    DEFAULT_BACKEND_URL,
    DEMO_PRESETS,
    fetch_backend_health,
    get_decision_color,
    get_severity_color,
    load_benchmark_report,
    load_markdown_file,
    scan_text,
)

# ---------------------------------------------------------------------------
# Streamlit Page Config & Theme Tokens
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PromptFence Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Premium Neomorphic + Spatial Dark Theme CSS
st.markdown(
    """
    <style>
    /* =====================================================================
       1. SPATIAL & NEUMORPHIC THEME FOUNDATION
       ===================================================================== */
    :root {
        --bg-main: #0A0D16;
        --surface-elevated: #141A28;
        --surface-elevated-hover: #1A2234;
        --surface-inset: #0D1220;
        --accent-periwinkle: #8B9BFF;
        --accent-cyan: #5DE4FF;
        --text-primary: #F3F5FF;
        --text-secondary: #A0AAC0;
        --text-muted: #64748B;
        --border-subtle: rgba(255, 255, 255, 0.07);
        --border-accent: rgba(139, 155, 255, 0.25);
        --status-allow: #10B981;
        --status-review: #F59E0B;
        --status-block: #EF4444;
        --radius-panel: 18px;
        --radius-control: 14px;
        --radius-pill: 9999px;
    }

    /* Top-level background with subtle ambient radial gradients */
    .stApp {
        background-color: var(--bg-main) !important;
        background-image: 
            radial-gradient(circle at 12% 12%, rgba(139, 155, 255, 0.07) 0%, transparent 40%),
            radial-gradient(circle at 88% 88%, rgba(93, 228, 255, 0.05) 0%, transparent 45%),
            radial-gradient(circle at 50% 50%, rgba(10, 13, 22, 1) 0%, rgba(10, 13, 22, 1) 100%) !important;
        background-attachment: fixed !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "SF Pro Display", Inter, sans-serif !important;
    }

    /* Reduce default top padding */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1280px !important;
    }

    /* Sidebar spatial styling */
    [data-testid="stSidebar"] {
        background-color: var(--surface-inset) !important;
        border-right: 1px solid var(--border-subtle) !important;
        box-shadow: inset -1px 0 0 0 rgba(255, 255, 255, 0.02) !important;
    }

    [data-testid="stSidebar"] * {
        color: var(--text-primary) !important;
    }

    [data-testid="stSidebar"] hr {
        border-color: var(--border-subtle) !important;
        margin: 1.2rem 0 !important;
    }

    /* =====================================================================
       2. REFINED HEADER & STATUS STRIP
       ===================================================================== */
    .spatial-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.25rem 1.6rem;
        background: var(--surface-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-panel);
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.6), inset 0 1px 1px 0 rgba(255, 255, 255, 0.08);
        margin-bottom: 1.75rem;
    }

    .brand-group {
        display: flex;
        align-items: center;
        gap: 1rem;
    }

    .brand-mark {
        width: 44px;
        height: 44px;
        border-radius: 12px;
        background: linear-gradient(135deg, rgba(139, 155, 255, 0.2) 0%, rgba(93, 228, 255, 0.1) 100%);
        border: 1px solid var(--border-accent);
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 12px rgba(139, 155, 255, 0.15);
    }

    .brand-text h1 {
        font-size: 1.45rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.02em;
        background: linear-gradient(120deg, #F3F5FF 0%, #8B9BFF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .brand-text p {
        font-size: 0.85rem;
        color: var(--text-secondary);
        margin: 0.15rem 0 0 0;
        letter-spacing: 0.01em;
    }

    .status-strip {
        display: flex;
        align-items: center;
        gap: 0.85rem;
        flex-wrap: wrap;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        padding: 0.35rem 0.85rem;
        border-radius: var(--radius-pill);
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        background: var(--surface-inset);
        border: 1px solid var(--border-subtle);
        color: var(--text-secondary);
    }

    .status-pill.online {
        border-color: rgba(16, 185, 129, 0.3);
        color: #A7F3D0;
    }

    .status-pill.offline {
        border-color: rgba(239, 68, 68, 0.3);
        color: #FECACA;
    }

    .dot-indicator {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }

    .dot-indicator.green {
        background-color: var(--status-allow);
        box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
    }

    .dot-indicator.amber {
        background-color: var(--status-review);
        box-shadow: 0 0 8px rgba(245, 158, 11, 0.6);
    }

    .dot-indicator.red {
        background-color: var(--status-block);
        box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
    }

    /* =====================================================================
       3. NEUMORPHIC INSET INPUTS & CONTROLS
       ===================================================================== */
    .stTextArea textarea {
        background-color: var(--surface-inset) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-control) !important;
        padding: 1rem 1.1rem !important;
        font-size: 0.95rem !important;
        font-family: inherit !important;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.5), 0 1px 0 rgba(255, 255, 255, 0.03) !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }

    .stTextArea textarea:focus {
        border-color: var(--accent-periwinkle) !important;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.5), 0 0 0 2px rgba(139, 155, 255, 0.2) !important;
        outline: none !important;
    }

    /* Selectbox Neomorphic surface */
    div[data-baseweb="select"] > div {
        background-color: var(--surface-inset) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-control) !important;
        color: var(--text-primary) !important;
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4) !important;
    }

    /* Primary Scan Button — Electric Periwinkle */
    .stButton button[kind="primary"] {
        background: linear-gradient(135deg, #8B9BFF 0%, #6366F1 100%) !important;
        color: #FFFFFF !important;
        border: 1px solid rgba(255, 255, 255, 0.18) !important;
        border-radius: var(--radius-control) !important;
        padding: 0.65rem 1.8rem !important;
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.02em !important;
        box-shadow: 0 4px 18px rgba(139, 155, 255, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .stButton button[kind="primary"]:hover {
        background: linear-gradient(135deg, #9BA9FF 0%, #7074F4 100%) !important;
        box-shadow: 0 6px 22px rgba(139, 155, 255, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.3) !important;
        transform: translateY(-1px) !important;
    }

    /* Secondary preset buttons */
    .stButton button[kind="secondary"] {
        background-color: var(--surface-elevated) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        padding: 0.45rem 0.95rem !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25) !important;
        transition: all 0.15s ease !important;
    }

    .stButton button[kind="secondary"]:hover {
        background-color: var(--surface-elevated-hover) !important;
        border-color: var(--border-accent) !important;
        color: var(--accent-periwinkle) !important;
    }

    /* =====================================================================
       4. ELEVATED RESULT PANELS & DECISION CARDS
       ===================================================================== */
    .spatial-card {
        background: var(--surface-elevated);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-panel);
        padding: 1.4rem;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.6), inset 0 1px 1px 0 rgba(255, 255, 255, 0.05);
        margin-bottom: 1.25rem;
    }

    .decision-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.35rem 1.6rem;
        border-radius: var(--radius-panel);
        margin-bottom: 1.25rem;
        border: 1px solid var(--border-subtle);
        box-shadow: 0 12px 32px -8px rgba(0, 0, 0, 0.7);
    }

    .decision-banner.allow {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(20, 26, 40, 0.9) 100%);
        border-color: rgba(16, 185, 129, 0.35);
    }

    .decision-banner.review {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(20, 26, 40, 0.9) 100%);
        border-color: rgba(245, 158, 11, 0.35);
    }

    .decision-banner.block {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.14) 0%, rgba(20, 26, 40, 0.9) 100%);
        border-color: rgba(239, 68, 68, 0.35);
    }

    .decision-title-group {
        display: flex;
        align-items: center;
        gap: 1.2rem;
    }

    .decision-tag {
        font-size: 1.15rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        padding: 0.4rem 1.25rem;
        border-radius: var(--radius-pill);
        color: #FFFFFF;
        text-transform: uppercase;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    }

    .decision-tag.allow { background-color: var(--status-allow); }
    .decision-tag.review { background-color: var(--status-review); }
    .decision-tag.block { background-color: var(--status-block); }

    .decision-headline {
        font-size: 1.05rem;
        font-weight: 600;
        color: var(--text-primary);
    }

    .decision-subtext {
        font-size: 0.82rem;
        color: var(--text-secondary);
        margin-top: 0.15rem;
    }

    .risk-score-display {
        text-align: right;
    }

    .risk-score-num {
        font-size: 2.1rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1;
    }

    .risk-score-denom {
        font-size: 0.9rem;
        color: var(--text-muted);
        font-weight: 500;
    }

    .finding-item {
        background: var(--surface-inset);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.1rem;
        margin-bottom: 0.85rem;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
    }

    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.4rem;
    }

    .severity-badge {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 0.2rem 0.55rem;
        border-radius: 6px;
    }

    .evidence-quote {
        background: #080B12;
        border-left: 3px solid var(--accent-periwinkle);
        border-radius: 0 6px 6px 0;
        padding: 0.55rem 0.75rem;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.82rem;
        color: #E2E8F0;
        margin-top: 0.55rem;
        word-break: break-all;
    }

    /* Metric cards in benchmark page */
    [data-testid="stMetric"] {
        background-color: var(--surface-elevated) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: var(--radius-control) !important;
        padding: 1rem 1.25rem !important;
        box-shadow: 0 6px 20px -4px rgba(0, 0, 0, 0.4) !important;
    }

    [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 800 !important;
        font-size: 1.75rem !important;
    }

    [data-testid="stMetricLabel"] {
        color: var(--text-secondary) !important;
        font-size: 0.8rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.04em !important;
    }

    /* Empty state card */
    .empty-state {
        text-align: center;
        padding: 3rem 1.5rem;
        background: var(--surface-elevated);
        border: 1px dashed var(--border-subtle);
        border-radius: var(--radius-panel);
    }

    .empty-icon {
        width: 48px;
        height: 48px;
        margin: 0 auto 1rem auto;
        border-radius: 14px;
        background: rgba(139, 155, 255, 0.1);
        display: flex;
        align-items: center;
        justify-content: center;
        color: var(--accent-periwinkle);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Sidebar: Compact Controls & System Telemetry
# ---------------------------------------------------------------------------

st.sidebar.markdown(
    """
    <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0 1rem 0;">
        <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(139, 155, 255, 0.18); border: 1px solid rgba(139, 155, 255, 0.3); display: flex; align-items: center; justify-content: center; font-size: 1.05rem;">
            🛡️
        </div>
        <div>
            <div style="font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; color: #F3F5FF;">PromptFence</div>
            <div style="font-size: 0.72rem; color: #A0AAC0; text-transform: uppercase; letter-spacing: 0.05em;">Security Console</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Detection Mode Selector
detection_mode = st.sidebar.selectbox(
    "Detection Mode",
    options=["hybrid", "rules_only", "llm_only"],
    index=0,
    format_func=lambda m: {
        "hybrid": "Hybrid (Rules + Gemma 4)",
        "rules_only": "Rules Only (<1 ms)",
        "llm_only": "Gemma 4 Only (Ollama)",
    }[m],
    help="Select the active detection pipeline.",
)

# Navigation
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Console View",
    ["Security Inspection", "Benchmark Analytics", "Attack Demonstrations", "Architecture & Defense"],
    index=0,
)

# Backend connection telemetry
st.sidebar.markdown("---")
st.sidebar.markdown("<div style='font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #A0AAC0; margin-bottom: 0.5rem;'>System Readiness</div>", unsafe_allow_html=True)

with st.sidebar.expander("API Endpoint Settings", expanded=False):
    backend_url = st.text_input(
        "FastAPI URL",
        value=DEFAULT_BACKEND_URL,
        label_visibility="collapsed",
    )
if "backend_url" not in locals():
    backend_url = DEFAULT_BACKEND_URL

# Live health check
health = fetch_backend_health(backend_url)

if health["online"]:
    ollama_ready = health["ollama"] == "available"
    st.sidebar.markdown(
        f"""
        <div style="background: #0D1220; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 10px; padding: 0.65rem 0.85rem; font-size: 0.78rem;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.35rem;">
                <span style="color: #A0AAC0;">FastAPI Engine:</span>
                <span style="color: #10B981; font-weight: 600;">● Online</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.35rem;">
                <span style="color: #A0AAC0;">Local Ollama:</span>
                <span style="color: {'#10B981' if ollama_ready else '#F59E0B'}; font-weight: 600;">
                    {'● Ready' if ollama_ready else '▲ Unavailable'}
                </span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #A0AAC0;">Active Model:</span>
                <span style="color: #8B9BFF; font-family: monospace;">{health['model']}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.sidebar.markdown(
        f"""
        <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 10px; padding: 0.65rem 0.85rem; font-size: 0.78rem; color: #FECACA;">
            <div style="font-weight: 600; margin-bottom: 0.25rem;">■ Backend Offline</div>
            <div>FastAPI is unreachable at <code>{backend_url}</code>.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.sidebar.caption("PromptFence v0.1.0 • Spatial Console")


# ---------------------------------------------------------------------------
# View 1: Security Inspection (Main Scanner)
# ---------------------------------------------------------------------------

if page == "Security Inspection":
    # Compact Spatial Header with real status
    api_pill_class = "online" if health["online"] else "offline"
    api_dot = "green" if health["online"] else "red"
    api_label = f"API Online (v{health.get('version', '0.2.0')})" if health["online"] else "API Offline"
    model_name = health.get("model") or "gemma4:e2b"
    ollama_ready = health.get("ollama") == "available"
    mode_label = {
        "hybrid": "HYBRID PIPELINE",
        "rules_only": "RULES ONLY",
        "llm_only": "GEMMA 4 ONLY",
    }[detection_mode]

    st.markdown(
        f"""
        <div class="spatial-header">
            <div class="brand-group">
                <div class="brand-mark">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#8B9BFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="m9 12 2 2 4-4"/>
                    </svg>
                </div>
                <div class="brand-text">
                    <h1>PromptFence</h1>
                    <p>Inspect untrusted content before an AI agent trusts it.</p>
                </div>
            </div>
            <div class="status-strip">
                <div class="status-pill {api_pill_class}">
                    <span class="dot-indicator {api_dot}"></span>
                    <span>{api_label}</span>
                </div>
                <div class="status-pill" style="border-color: rgba(93, 228, 255, 0.3); color: #5DE4FF;">
                    <span class="dot-indicator {'green' if ollama_ready else 'amber'}"></span>
                    <span>MODEL: {model_name}</span>
                </div>
                <div class="status-pill" style="border-color: rgba(139, 155, 255, 0.3); color: #8B9BFF;">
                    <span>{mode_label}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not health["online"]:
        st.error(
            f"**FastAPI backend unavailable at `{backend_url}`.**\n\n"
            "Run this command in a separate PowerShell window to launch the backend:\n\n"
            "```powershell\n"
            ".\\.venv\\Scripts\\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload\n"
            "```"
        )

    # Main Scanner Panel
    st.markdown("### Security inspection")

    # Sample prompt chips
    st.caption("Quick-load curated test scenarios:")
    chip_cols = st.columns(4)
    with chip_cols[0]:
        if st.button("OVERRIDE-001 (Attack)", key="chip_1", use_container_width=True, type="secondary"):
            st.session_state["scanner_input"] = DEMO_PRESETS[0]["text"]
    with chip_cols[1]:
        if st.button("TRAP-001 (Email Trap)", key="chip_2", use_container_width=True, type="secondary"):
            st.session_state["scanner_input"] = DEMO_PRESETS[1]["text"]
    with chip_cols[2]:
        if st.button("TRAP-006 (Code Tutorial)", key="chip_3", use_container_width=True, type="secondary"):
            st.session_state["scanner_input"] = DEMO_PRESETS[3]["text"]
    with chip_cols[3]:
        if st.button("TOOL-005 (Tool Attack)", key="chip_4", use_container_width=True, type="secondary"):
            st.session_state["scanner_input"] = DEMO_PRESETS[4]["text"]

    with st.expander("📁 Or upload a document / text file (.txt, .md, .json, .csv, .py)", expanded=False):
        uploaded_doc = st.file_uploader(
            "Upload untrusted document to inspect",
            type=["txt", "md", "json", "csv", "py"],
            key="file_upload_scanner",
            label_visibility="collapsed",
        )
        if uploaded_doc is not None:
            try:
                doc_bytes = uploaded_doc.read()
                doc_text = doc_bytes.decode("utf-8", errors="replace")
                st.session_state["scanner_input"] = doc_text
                st.success(f"Loaded '{uploaded_doc.name}' ({len(doc_text):,} characters) into inspection field.")
            except Exception as e:
                st.error(f"Failed to read file: {e}")

    current_input = st.session_state.get("scanner_input", "")

    input_text = st.text_area(
        "Untrusted Agent Input",
        value=current_input,
        height=140,
        placeholder="Paste user prompt, tool output, or agent instruction to scan for injection vectors...",
        label_visibility="collapsed",
    )

    col_btn, col_info = st.columns([1, 4])
    with col_btn:
        scan_clicked = st.button("Analyze content", type="primary", use_container_width=True)
    with col_info:
        st.markdown(
            f"<div style='color: #A0AAC0; font-size: 0.85rem; padding-top: 0.55rem;'>"
            f"Engine: <strong>{mode_label}</strong> • Model: <code>{model_name}</code> • Strict policy boundaries"
            f"</div>",
            unsafe_allow_html=True,
        )

    # Inspection Execution
    if scan_clicked:
        if not input_text or not input_text.strip():
            st.warning("Please provide input text or choose an example prompt above.")
        elif not health["online"]:
            st.error("Cannot scan while FastAPI backend is offline. Start backend and retry.")
        else:
            with st.spinner("Analyzing content across security tiers..."):
                try:
                    scan_result = scan_text(input_text, mode=detection_mode, base_url=backend_url)
                    st.session_state["last_scan_result"] = scan_result
                except RuntimeError as exc:
                    st.error(str(exc))
                    st.session_state["last_scan_result"] = None

    # Result Presentation
    scan_result = st.session_state.get("last_scan_result")

    if scan_result:
        decision = scan_result.get("decision", "unknown").upper()
        risk_score = scan_result.get("risk_score", 0)
        reasons = scan_result.get("reasons", [])
        findings = scan_result.get("findings", [])
        detector_statuses = scan_result.get("detector_status") or scan_result.get("detector_statuses") or []
        latency_ms = scan_result.get("processing_time_ms")

        # Refined Decision Banner
        banner_class = decision.lower()
        dec_color = get_decision_color(decision)
        headline = {
            "ALLOW": "Action Permitted — Input Cleared by Policy",
            "REVIEW": "Action Flagged — Human Review or Restriction Required",
            "BLOCK": "Action Blocked — High-Risk Injection Vector Detected",
        }.get(decision, "Security Status Evaluated")

        subtext = {
            "ALLOW": "No high-severity injection indicators detected; risk score is within acceptable boundaries.",
            "REVIEW": "Indicators exceed safe threshold. Recommend human approval or restricted execution sandbox.",
            "BLOCK": "Threat exceeds critical policy threshold. Direct agent execution should be rejected immediately.",
        }.get(decision, "")

        st.markdown(
            f"""
            <div class="decision-banner {banner_class}">
                <div class="decision-title-group">
                    <span class="decision-tag {banner_class}">{decision}</span>
                    <div>
                        <div class="decision-headline">{headline}</div>
                        <div class="decision-subtext">{subtext}</div>
                    </div>
                </div>
                <div class="risk-score-display">
                    <div style="font-size: 0.72rem; color: #A0AAC0; text-transform: uppercase; letter-spacing: 0.05em;">Risk Score</div>
                    <div class="risk-score-num" style="color: {dec_color};">{risk_score}<span class="risk-score-denom">/100</span></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Overview Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Risk Score", f"{risk_score} / 100")
        with m2:
            st.metric("Active Findings", len(findings))
        with m3:
            unique_cats = len({f.get("category") for f in findings})
            st.metric("Flagged Categories", unique_cats)
        with m4:
            latency_str = f"{latency_ms:.1f} ms" if latency_ms is not None else "N/A"
            st.metric("Scan Latency", latency_str)

        # Policy Reasons & Indicators
        col_findings, col_reasons = st.columns([3, 2])

        with col_findings:
            st.markdown("#### Detected Indicators & Evidence")
            if findings:
                for f in findings:
                    f_cat = f.get("category", "unknown").replace("_", " ").title()
                    f_sev = f.get("severity", "unknown").lower()
                    f_det = f.get("detector", "unknown")
                    f_ev = f.get("evidence", "")
                    f_ind = f.get("matched_indicator", "")
                    f_ver = f.get("evidence_verified", True)
                    f_conf = f.get("confidence")

                    sev_color = get_severity_color(f_sev)

                    badge_ver = (
                        '<span style="background: rgba(16, 185, 129, 0.15); color: #10B981; font-size: 0.72rem; padding: 2px 7px; border-radius: 4px; font-weight: 600;">✓ Verified Quote</span>'
                        if f_ver
                        else '<span style="background: rgba(239, 68, 68, 0.15); color: #EF4444; font-size: 0.72rem; padding: 2px 7px; border-radius: 4px; font-weight: 600;">⚠ Unverified</span>'
                    )

                    badge_conf = (
                        f'<span style="background: rgba(139, 155, 255, 0.15); color: #8B9BFF; font-size: 0.72rem; padding: 2px 7px; border-radius: 4px; font-weight: 600;">Conf: {f_conf:.2f}</span>'
                        if f_conf is not None
                        else ""
                    )

                    st.markdown(
                        f"""
                        <div class="finding-item" style="border-left: 3px solid {sev_color};">
                            <div class="finding-header">
                                <div>
                                    <span style="font-weight: 700; color: #F3F5FF; font-size: 0.95rem;">{f_cat}</span>
                                    <span class="severity-badge" style="background: {sev_color}22; color: {sev_color}; margin-left: 0.4rem;">{f_sev}</span>
                                    <span style="color: #64748B; font-size: 0.78rem; margin-left: 0.4rem;">via {f_det}</span>
                                </div>
                                <div style="display: flex; gap: 0.35rem;">
                                    {badge_ver}
                                    {badge_conf}
                                </div>
                            </div>
                            <div style="font-size: 0.85rem; color: #A0AAC0; margin-top: 0.3rem;">{f_ind}</div>
                            <div class="evidence-quote">"{f_ev}"</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    """
                    <div style="background: #0D1220; border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 12px; padding: 1.2rem; color: #A7F3D0; font-size: 0.88rem;">
                        ✓ No adversarial patterns, prompt injection phrases, or suspicious tools were flagged in this input.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with col_reasons:
            st.markdown("#### Policy Engine Evaluation")
            st.markdown("<div style='font-size: 0.85rem; color: #A0AAC0; margin-bottom: 0.5rem;'>Explicit enforcement criteria applied:</div>", unsafe_allow_html=True)
            if reasons:
                for r in reasons:
                    st.markdown(f"- <span style='font-size: 0.86rem; color: #F3F5FF;'>{r}</span>", unsafe_allow_html=True)
            else:
                st.markdown("- <span style='font-size: 0.86rem; color: #A0AAC0;'>All category risk scores remained below the review threshold (25).</span>", unsafe_allow_html=True)

            with st.expander("Detector Telemetry Details", expanded=False):
                for s in detector_statuses:
                    s_det = s.get("name") or s.get("detector") or "detector"
                    s_st = s.get("status", "ok")
                    s_avail = s.get("available", True)
                    s_err = s.get("error")
                    is_ok = (s_st in ("ok", "success")) and s_avail
                    color = "#10B981" if is_ok else ("#A0AAC0" if s_st == "skipped" else "#EF4444")
                    status_text = "Operational" if is_ok else (s_st or "unavailable")
                    st.markdown(f"<span style='color: {color};'>●</span> <strong>{s_det}</strong>: {status_text} {f'({s_err})' if s_err else ''}", unsafe_allow_html=True)

    elif not scan_clicked:
        # Empty state
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div style="font-weight: 600; font-size: 1.05rem; color: #F3F5FF;">Security Console Ready</div>
                <div style="font-size: 0.85rem; color: #A0AAC0; max-width: 480px; margin: 0.4rem auto 0 auto;">
                    Paste prompt text or untrusted tool data into the inspection field above, or pick a curated preset, then click <strong>Analyze content</strong>.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# View 2: Benchmark Analytics
# ---------------------------------------------------------------------------

elif page == "Benchmark Analytics":
    st.markdown('<div class="main-header" style="font-size: 1.6rem; font-weight: 700; color: #F3F5FF;">📊 Security Benchmark Analytics</div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size: 0.9rem; color: #A0AAC0; margin-bottom: 1.5rem;">'
        'Verified metrics evaluated across the <strong>61 synthetic test cases</strong> in <code>data/benchmark_v1.jsonl</code>. Loaded directly from actual evaluation run reports.'
        '</div>',
        unsafe_allow_html=True,
    )

    report_configs = {
        "Improved Hybrid (Gemma 4 + Rules)": {
            "json": "benchmark_results_hybrid_improved.json",
            "md": "benchmark_report_hybrid_improved.md",
            "type": "hybrid",
        },
        "Improved Rules-Only (Deterministic)": {
            "json": "benchmark_results_rules_improved.json",
            "md": "benchmark_report_rules_improved.md",
            "type": "rules",
        },
        "Baseline Hybrid (Pre-Audit)": {
            "json": "benchmark_results.json",
            "md": "benchmark_report.md",
            "type": "baseline",
        },
    }

    selected_report_name = st.selectbox(
        "Evaluation Report Source",
        options=list(report_configs.keys()),
        index=0,
    )

    cfg = report_configs[selected_report_name]
    data = load_benchmark_report(cfg["json"])

    if data:
        metrics = data.get("metrics", {})
        cm = data.get("confusion_matrix", {})
        cat_metrics = data.get("category_metrics", {})
        latencies = data.get("latencies", {})
        evaluations = data.get("evaluations", [])

        # Executive Metrics
        st.markdown("#### Performance Metrics")
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Accuracy", f"{metrics.get('accuracy', 0):.1%}")
        with c2:
            st.metric("Precision", f"{metrics.get('precision', 0):.1%}")
        with c3:
            st.metric("Recall (TPR)", f"{metrics.get('recall', 0):.1%}")
        with c4:
            st.metric("F1-Score", f"{metrics.get('f1_score', 0):.4f}")
        with c5:
            st.metric("False Positive Rate", f"{metrics.get('false_positive_rate', 0):.1%}")

        # Confusion Matrix Spatial Panel
        st.markdown("#### Confusion Matrix (Dataset Size: 61 Samples)")
        tp = cm.get("true_positives", 0)
        fp = cm.get("false_positives", 0)
        tn = cm.get("true_negatives", 0)
        fn = cm.get("false_negatives", 0)

        cm_c1, cm_c2 = st.columns(2)
        with cm_c1:
            st.markdown(
                f"""
                <div style="background: #141A28; border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 14px; padding: 1.1rem; margin-bottom: 0.75rem;">
                    <div style="font-size: 0.75rem; color: #10B981; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">True Positives (Attacks Flagged)</div>
                    <div style="font-size: 2rem; font-weight: 800; color: #F3F5FF; margin: 0.2rem 0;">{tp}</div>
                    <div style="font-size: 0.78rem; color: #A0AAC0;">Attacks accurately classified as Review or Block.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""
                <div style="background: #141A28; border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 14px; padding: 1.1rem;">
                    <div style="font-size: 0.75rem; color: #EF4444; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">False Negatives (Missed Attacks)</div>
                    <div style="font-size: 2rem; font-weight: 800; color: #F3F5FF; margin: 0.2rem 0;">{fn}</div>
                    <div style="font-size: 0.78rem; color: #A0AAC0;">Attacks erroneously allowed by policy.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with cm_c2:
            st.markdown(
                f"""
                <div style="background: #141A28; border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 14px; padding: 1.1rem; margin-bottom: 0.75rem;">
                    <div style="font-size: 0.75rem; color: #F59E0B; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">False Positives (Benign Flagged)</div>
                    <div style="font-size: 2rem; font-weight: 800; color: #F3F5FF; margin: 0.2rem 0;">{fp}</div>
                    <div style="font-size: 0.78rem; color: #A0AAC0;">Safe inputs erroneously escalated.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f"""
                <div style="background: #141A28; border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 14px; padding: 1.1rem;">
                    <div style="font-size: 0.75rem; color: #10B981; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">True Negatives (Benign Cleared)</div>
                    <div style="font-size: 2rem; font-weight: 800; color: #F3F5FF; margin: 0.2rem 0;">{tn}</div>
                    <div style="font-size: 0.78rem; color: #A0AAC0;">Safe everyday inputs permitted through.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Operational Latency
        st.markdown("#### Operational Latency & Inferences")
        l1, l2, l3, l4 = st.columns(4)
        with l1:
            st.metric("Mean Latency", f"{latencies.get('mean_ms', 0):.2f} ms")
        with l2:
            st.metric("P95 Latency", f"{latencies.get('p95_ms', 0):.2f} ms")
        with l3:
            st.metric("Successful Inferences", data.get("successful_inferences", 0))
        with l4:
            st.metric("Failed Inferences", data.get("failed_inferences", 0))

        # Category Breakdown
        st.markdown("#### Category-Level Metrics (One-vs-Rest)")
        st.caption(
            "Each category is evaluated independently. A category False Positive occurs when a category is triggered "
            "on an input where it was not present in ground truth (including benign inputs or attacks of another category)."
        )

        cat_table = []
        for cname, cinfo in cat_metrics.items():
            cat_table.append(
                {
                    "Category": cname,
                    "Support": cinfo.get("support", 0),
                    "TP": cinfo.get("tp", 0),
                    "FP": cinfo.get("fp", 0),
                    "FN": cinfo.get("fn", 0),
                    "Precision": f"{cinfo.get('precision', 0):.1%}",
                    "Recall": f"{cinfo.get('recall', 0):.1%}",
                    "F1-Score": f"{cinfo.get('f1_score', 0):.4f}",
                }
            )
        st.table(cat_table)

    else:
        st.warning(f"Could not load `{cfg['json']}`. Showing markdown report fallback:")
        md = load_markdown_file(cfg["md"])
        if md:
            st.markdown(md)


# ---------------------------------------------------------------------------
# View 3: Attack Demonstrations
# ---------------------------------------------------------------------------

elif page == "Attack Demonstrations":
    st.markdown('<div class="main-header" style="font-size: 1.6rem; font-weight: 700; color: #F3F5FF;">🎯 Interactive Attack Demonstrations</div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size: 0.9rem; color: #A0AAC0; margin-bottom: 1.5rem;">'
        'Curated examples demonstrating defense against prompt injection while preventing false alarms on benign queries.'
        '</div>',
        unsafe_allow_html=True,
    )

    for item in DEMO_PRESETS:
        with st.expander(f"[{item['id']}] {item['title']} — Expected: {item['expected'].upper()}", expanded=True):
            col_left, col_btn = st.columns([5, 1])
            with col_left:
                st.markdown(f"**Classification**: `{item['category']}`")
                st.markdown(f"*{item['description']}*")
                st.code(item["text"], language="text")
            with col_btn:
                st.write("")
                st.write("")
                if st.button(f"Load into Scanner", key=f"demo_btn_{item['id']}", use_container_width=True):
                    st.session_state["scanner_input"] = item["text"]
                    st.info("Loaded into Security Inspection. Switch views to analyze!")


# ---------------------------------------------------------------------------
# View 4: Architecture & Defense
# ---------------------------------------------------------------------------

elif page == "Architecture & Defense":
    st.markdown('<div class="main-header" style="font-size: 1.6rem; font-weight: 700; color: #F3F5FF;">🏗️ Architecture & Security Boundaries</div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size: 0.9rem; color: #A0AAC0; margin-bottom: 1.5rem;">'
        'Multi-tiered defense harness combining sub-millisecond pattern rules with local Gemma 4 contextual reasoning.'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="spatial-card">
            <h4 style="margin-top: 0; color: #8B9BFF;">4-Tier Defense Pipeline</h4>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 1rem;">
                <div style="background: #0D1220; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.06);">
                    <div style="font-size: 0.75rem; color: #8B9BFF; font-weight: 700; text-transform: uppercase;">Tier 1</div>
                    <div style="font-weight: 700; margin: 0.25rem 0;">Deterministic Rules</div>
                    <div style="font-size: 0.8rem; color: #A0AAC0;">Sub-millisecond regex matching across 4 attack categories with fixed severity scores.</div>
                </div>
                <div style="background: #0D1220; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.06);">
                    <div style="font-size: 0.75rem; color: #5DE4FF; font-weight: 700; text-transform: uppercase;">Tier 2</div>
                    <div style="font-weight: 700; margin: 0.25rem 0;">Gemma 4 E2B</div>
                    <div style="font-size: 0.8rem; color: #A0AAC0;">Local Ollama reasoning for semantic ambiguity, roleplay evasions, and strict JSON output.</div>
                </div>
                <div style="background: #0D1220; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.06);">
                    <div style="font-size: 0.75rem; color: #F59E0B; font-weight: 700; text-transform: uppercase;">Tier 3</div>
                    <div style="font-weight: 700; margin: 0.25rem 0;">Finding Merger</div>
                    <div style="font-size: 0.8rem; color: #A0AAC0;">Deduplicates overlapping evidence spans and unifies findings with calibrated weights.</div>
                </div>
                <div style="background: #0D1220; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.06);">
                    <div style="font-size: 0.75rem; color: #10B981; font-weight: 700; text-transform: uppercase;">Tier 4</div>
                    <div style="font-weight: 700; margin: 0.25rem 0;">Policy Engine</div>
                    <div style="font-size: 0.8rem; color: #A0AAC0;">Separates detection from policy: applies context discounts, verification weights, and decisions.</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_arch1, col_arch2 = st.columns(2)
    with col_arch1:
        st.markdown(
            """
            <div class="spatial-card">
                <h4 style="margin-top: 0; color: #F3F5FF;">Core Principle: Finding ≠ Decision</h4>
                <p style="font-size: 0.88rem; color: #A0AAC0; line-height: 1.6;">
                    A <strong>detector finding</strong> is an observation: an indicator was spotted in the text.<br>
                    A <strong>policy decision</strong> is an enforcement action: whether the agent may proceed.
                </p>
                <p style="font-size: 0.88rem; color: #A0AAC0; line-height: 1.6;">
                    The policy engine independently evaluates risk score thresholds (<code>allow &lt; 25</code>, <code>review 25–59</code>, <code>block ≥ 60</code>), discounts benign mentions of task parameters (email drafts, calendar invites), and scales unverified LLM quotes.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_arch2:
        st.markdown(
            """
            <div class="spatial-card">
                <h4 style="margin-top: 0; color: #F3F5FF;">Local Privacy & Resilience</h4>
                <p style="font-size: 0.88rem; color: #A0AAC0; line-height: 1.6;">
                    PromptFence executes completely offline on your host machine.
                    No user prompts or credentials are sent to external APIs.
                </p>
                <p style="font-size: 0.88rem; color: #A0AAC0; line-height: 1.6;">
                    If Ollama is stopped or times out, PromptFence does not fail open or crash: it marks the LLM detector as failed, preserves deterministic rule findings, and flags partial results in the response.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
