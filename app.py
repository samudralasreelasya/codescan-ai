import streamlit as st
import matplotlib.pyplot as plt
import sqlite3
import hashlib
from datetime import datetime

# ─── Page Config ────────────────────────────────────────────────
st.set_page_config(
    page_title="CodeScan AI",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─── Groq AI ────────────────────────────────────────────────────
GROQ_API_KEY = st.secrets.get("GROQ_API_KEY", "")

def ask_groq(prompt):
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "user", "content": prompt}
    ]
)
        return response.choices[0].message.content
    except Exception as e:
        return f"AI unavailable: {str(e)}"

# ─── Database ────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("codescan.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        language TEXT NOT NULL,
        lines_analyzed INTEGER,
        bugs_found INTEGER,
        quality_score INTEGER,
        risk_score INTEGER,
        complexity TEXT,
        scanned_at TEXT NOT NULL)""")
    existing = [r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()]
    for col, defval in [("complexity","'Unknown'"),("scanned_at","'N/A'"),("risk_score","0")]:
        if col not in existing:
            c.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT {defval}")
    conn.commit()
    conn.close()

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def register_user(username, email, password):
    try:
        conn = sqlite3.connect("codescan.db")
        c = conn.cursor()
        c.execute("INSERT INTO users (username,email,password,created_at) VALUES (?,?,?,?)",
                  (username, email, hash_password(password),
                   datetime.now().strftime("%d %b %Y %H:%M")))
        conn.commit(); conn.close()
        return True, "Account created successfully!"
    except sqlite3.IntegrityError:
        return False, "Username or email already exists!"

def login_user(username, password):
    conn = sqlite3.connect("codescan.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?",
              (username, hash_password(password)))
    user = c.fetchone(); conn.close()
    return user

def save_scan(username, language, lines, bugs, quality, risk, complexity):
    conn = sqlite3.connect("codescan.db")
    c = conn.cursor()
    c.execute("""INSERT INTO scans
        (username,language,lines_analyzed,bugs_found,quality_score,risk_score,complexity,scanned_at)
        VALUES (?,?,?,?,?,?,?,?)""",
              (username, language, lines, bugs, quality, risk, complexity,
               datetime.now().strftime("%d %b %Y %H:%M")))
    conn.commit(); conn.close()

def get_user_scans(username):
    conn = sqlite3.connect("codescan.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE username=? ORDER BY id DESC", (username,))
    scans = c.fetchall(); conn.close()
    return scans

def get_all_stats():
    conn = sqlite3.connect("codescan.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans");       ts = c.fetchone()[0]
    c.execute("SELECT SUM(bugs_found) FROM scans"); tb = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM users");        tu = c.fetchone()[0]
    conn.close()
    return ts, tb, tu

# ─── Complexity ──────────────────────────────────────────────────
def calculate_complexity(lines):
    score = sum(1 for line in lines for kw in
                ["if ","elif ","else:","for ","while ","try:","except","and ","or "]
                if kw in line)
    if score <= 5:  return score, "Simple",   "#34d399"
    if score <= 15: return score, "Moderate", "#fb923c"
    return score,           "Complex",  "#f87171"

# ─── Bug Detection ───────────────────────────────────────────────
def analyze_python(lines):
    bugs, sugg = [], []
    rules = [
        ("except:",  "Bare except — catches all errors blindly",  "High",   "🔴", "Use `except Exception as e:` instead"),
        ("== True",  "Comparing to True using == is unnecessary", "Low",    "🟡", "Use `if variable:` instead"),
        ("print(",   "Debug print statement found",               "Low",    "🟡", "Replace with proper logging"),
        ("== None",  "Wrong None comparison",                     "Medium", "🟠", "Use `is None` instead"),
        ("eval(",    "eval() is dangerous — security risk",       "High",   "🔴", "Avoid eval() completely"),
        ("import *", "Wildcard import — bad practice",            "Medium", "🟠", "Import only what you need"),
    ]
    for i, line in enumerate(lines, 1):
        s = line.strip()
        for pattern, msg, sev, icon, fix in rules:
            if pattern in s:
                bugs.append((i, msg, sev, icon))
                sugg.append((i, fix))
        if len(line) > 100:
            bugs.append((i, "Line too long — hard to read", "Low", "🟡"))
            sugg.append((i, "Keep lines under 100 characters"))
    return bugs, sugg

def analyze_java(lines):
    bugs, sugg = [], []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if "catch(Exception" in s or "catch (Exception" in s:
            bugs.append((i, "Catching generic Exception — too broad", "High", "🔴"))
            sugg.append((i, "Catch specific exceptions like IOException"))
        if "System.out.println" in s:
            bugs.append((i, "Debug print statement found", "Low", "🟡"))
            sugg.append((i, "Use Logger instead"))
        if "== null" in s:
            bugs.append((i, "Null comparison without null-safety", "Medium", "🟠"))
            sugg.append((i, "Use Objects.isNull() or Optional"))
        if "e.printStackTrace()" in s:
            bugs.append((i, "printStackTrace() exposes internals", "Medium", "🟠"))
            sugg.append((i, "Use a proper logger instead"))
        if len(line) > 100:
            bugs.append((i, "Line too long — hard to read", "Low", "🟡"))
            sugg.append((i, "Keep lines under 100 characters"))
    return bugs, sugg

# ─── CSS ─────────────────────────────────────────────────────────
def load_css(dark_mode):
    if dark_mode:
        bg      = "#0a0a0f"
        surface = "#111827"
        border  = "#1f2937"
        text    = "#e2e8f0"
        muted   = "#94a3b8"
        accent  = "#a78bfa"
        inp     = "#1a1a2e"
        nav_bg  = "rgba(13,13,26,0.95)"
    else:
        bg      = "#f8fafc"
        surface = "#ffffff"
        border  = "#e2e8f0"
        text    = "#0f172a"
        muted   = "#64748b"
        accent  = "#6366f1"
        inp     = "#f1f5f9"
        nav_bg  = "rgba(255,255,255,0.95)"

    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Space Grotesk', sans-serif !important;
    }}

    /* ── Remove ALL Streamlit chrome ── */
    #MainMenu                               {{ visibility: hidden !important; }}
    footer                                  {{ visibility: hidden !important; }}
    header                                  {{ visibility: hidden !important; }}
    section[data-testid="stSidebar"]        {{ display: none !important; }}
    [data-testid="collapsedControl"]        {{ display: none !important; }}
    [data-testid="stSidebarCollapseButton"] {{ display: none !important; }}
    button[kind="header"]                   {{ display: none !important; }}

    .stApp {{ background: {bg} !important; }}

    .block-container {{
        padding: 80px 2.5rem 2rem 2.5rem !important;
        max-width: 100% !important;
    }}

    /* ══════════════════════════════════════
       FIXED TOP NAVBAR
    ══════════════════════════════════════ */
    .navbar {{
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 9999;
        background: {nav_bg};
        border-bottom: 1px solid {border};
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        height: 62px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 2rem;
        gap: 16px;
    }}
    .navbar-brand {{
        font-size: 1.15rem;
        font-weight: 700;
        background: linear-gradient(135deg, #a78bfa, #60a5fa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        white-space: nowrap;
        flex-shrink: 0;
    }}
    .navbar-links {{
        display: flex;
        align-items: center;
        gap: 4px;
        flex: 1;
        justify-content: center;
    }}
    .nav-pill {{
        padding: 7px 18px;
        border-radius: 20px;
        font-size: 0.88rem;
        font-weight: 500;
        color: {muted};
        cursor: pointer;
        transition: all 0.18s;
        border: none;
        background: transparent;
        font-family: 'Space Grotesk', sans-serif;
        white-space: nowrap;
        text-decoration: none;
        display: inline-block;
    }}
    .nav-pill:hover {{
        background: {surface};
        color: {accent};
    }}
    .nav-pill.active {{
        background: {surface};
        color: {accent};
        border: 1px solid {border};
    }}
    .navbar-right {{
        display: flex;
        align-items: center;
        gap: 10px;
        flex-shrink: 0;
    }}
    .nav-stats {{
        display: flex;
        gap: 14px;
        padding: 0 14px;
        border-left: 1px solid {border};
        border-right: 1px solid {border};
    }}
    .nav-stat {{
        display: flex;
        flex-direction: column;
        align-items: center;
        line-height: 1.25;
    }}
    .nav-stat-val  {{ font-size: 0.85rem; font-weight: 700; color: {accent}; }}
    .nav-stat-lbl  {{ font-size: 0.65rem; color: {muted}; text-transform: uppercase; letter-spacing: 0.5px; }}
    .nav-user {{
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 5px 12px 5px 6px;
        background: {surface};
        border: 1px solid {border};
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 500;
        color: {text};
        white-space: nowrap;
    }}
    .nav-avatar {{
        width: 28px; height: 28px;
        border-radius: 50%;
        background: linear-gradient(135deg, #6366f1, #a78bfa);
        display: flex; align-items: center; justify-content: center;
        font-size: 0.72rem; font-weight: 700; color: white;
        flex-shrink: 0;
    }}

    /* ── Hero ── */
    .hero {{
        background: linear-gradient(135deg, #0f0f1a 0%, #1a0a2e 50%, #0a1628 100%);
        border: 1px solid #2d2d4e;
        border-radius: 16px;
        padding: 44px 32px;
        margin-bottom: 32px;
        text-align: center;
    }}
    .hero h1 {{
        font-size: 2.8rem; font-weight: 700;
        background: linear-gradient(135deg, #a78bfa, #60a5fa, #34d399);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0 0 8px 0; letter-spacing: -0.5px;
    }}
    .hero p {{ color: #94a3b8; font-size: 1rem; margin: 0; }}

    /* ── Metric cards ── */
    .metric-card {{
        background: {surface}; border: 1px solid {border};
        border-radius: 12px; padding: 20px 16px;
        text-align: center; margin-bottom: 8px;
    }}
    .metric-value {{ font-size: 1.9rem; font-weight: 700; color: {accent}; line-height: 1.1; }}
    .metric-label {{ font-size: 0.7rem; color: {muted}; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 6px; }}

    /* ── Issue / Fix rows ── */
    .issue-row {{
        background: {surface}; border: 1px solid {border};
        border-left: 3px solid #6366f1; border-radius: 8px;
        padding: 10px 14px; margin-bottom: 8px; font-size: 0.88rem; color: {text};
    }}
    .fix-row {{
        background: {surface}; border: 1px solid {border};
        border-left: 3px solid #34d399; border-radius: 8px;
        padding: 10px 14px; margin-bottom: 8px; font-size: 0.88rem; color: {text};
    }}
    .history-row {{
        background: {surface}; border: 1px solid {border};
        border-radius: 10px; padding: 14px 18px; margin-bottom: 10px; color: {text};
    }}

    /* ── Chat bubbles ── */
    .chat-msg-user {{
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        color: white; border-radius: 16px 16px 4px 16px;
        padding: 12px 16px; margin: 8px 0 8px auto;
        font-size: 0.9rem; max-width: 75%; display: block;
    }}
    .chat-msg-ai {{
        background: {surface}; border: 1px solid {border};
        color: {text}; border-radius: 16px 16px 16px 4px;
        padding: 12px 16px; margin: 8px 0;
        font-size: 0.9rem; max-width: 75%; display: block;
    }}

    /* ── Section titles ── */
    .section-title {{
        font-size: 0.75rem; font-weight: 600; color: {accent};
        text-transform: uppercase; letter-spacing: 2.5px;
        margin: 24px 0 12px 0; padding-bottom: 8px;
        border-bottom: 1px solid {border};
    }}

    /* ── Badges ── */
    .badge-high   {{ background:#2d0f0f; color:#f87171; border:1px solid #7f1d1d; border-radius:6px; padding:2px 10px; font-size:0.72rem; }}
    .badge-medium {{ background:#2d1f0f; color:#fb923c; border:1px solid #7c2d12; border-radius:6px; padding:2px 10px; font-size:0.72rem; }}
    .badge-low    {{ background:#1a2d0f; color:#a3e635; border:1px solid #365314; border-radius:6px; padding:2px 10px; font-size:0.72rem; }}

    /* ── Inputs ── */
    .stTextInput input, .stTextArea textarea {{
        background: {inp} !important; border: 1px solid {border} !important;
        border-radius: 8px !important; color: {text} !important;
        font-family: 'JetBrains Mono', monospace !important; font-size: 0.88rem !important;
    }}
    .stTextInput input:focus, .stTextArea textarea:focus {{
        border-color: {accent} !important;
        box-shadow: 0 0 0 2px rgba(99,102,241,0.15) !important;
    }}

    /* ── Buttons ── */
    .stButton button {{
        background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
        color: white !important; border: none !important;
        border-radius: 10px !important; font-weight: 600 !important;
        width: 100% !important; padding: 10px !important;
        font-family: 'Space Grotesk', sans-serif !important;
        transition: opacity 0.2s !important;
    }}
    .stButton button:hover {{ opacity: 0.85 !important; }}

    /* ── Selectbox ── */
    .stSelectbox > div > div {{
        background: {inp} !important; border: 1px solid {border} !important;
        color: {text} !important; border-radius: 8px !important;
    }}

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab-list"] {{
        background: transparent !important;
        border-bottom: 1px solid {border} !important;
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {muted} !important; font-weight: 500 !important; padding: 10px 20px !important;
    }}
    .stTabs [aria-selected="true"] {{
        color: {accent} !important; border-bottom: 2px solid {accent} !important;
    }}
    hr {{ border-color: {border} !important; }}
    </style>
    """, unsafe_allow_html=True)

# ─── Init ────────────────────────────────────────────────────────
init_db()

defaults = {
    "logged_in": False, "username": "", "dark_mode": True,
    "chat_history": [], "last_code": "", "last_bugs": [],
    "last_fixed_code": "", "page": "analyzer",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

load_css(st.session_state.dark_mode)

# ════════════════════════════════════════════════════════════════
#  LOGIN / REGISTER
# ════════════════════════════════════════════════════════════════
if not st.session_state.logged_in:

    st.markdown("""
    <div class="hero">
        <h1>&#9889; CodeScan AI</h1>
        <p>AI-Powered Code Review &amp; Bug Prediction &mdash; Python &amp; Java</p>
    </div>""", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔐  Login", "📝  Register"])

    with tab1:
        st.markdown('<div class="section-title">Welcome Back</div>', unsafe_allow_html=True)
        u = st.text_input("Username", key="lu")
        p = st.text_input("Password", type="password", key="lp")
        if st.button("Login →", key="lbtn"):
            if u and p:
                user = login_user(u, p)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.username  = u
                    st.rerun()
                else:
                    st.error("❌ Wrong username or password")
            else:
                st.warning("Please fill in all fields")

    with tab2:
        st.markdown('<div class="section-title">Create Account</div>', unsafe_allow_html=True)
        nu = st.text_input("Username",         key="ru")
        ne = st.text_input("Email",            key="re")
        np = st.text_input("Password",         type="password", key="rp")
        cp = st.text_input("Confirm Password", type="password", key="rc")
        if st.button("Create Account →", key="rbtn"):
            if nu and ne and np and cp:
                if np != cp:       st.error("❌ Passwords do not match")
                elif len(np) < 6:  st.error("❌ Password must be at least 6 characters")
                else:
                    ok, msg = register_user(nu, ne, np)
                    st.success(f"✅ {msg}") if ok else st.error(f"❌ {msg}")
            else:
                st.warning("Please fill in all fields")

# ════════════════════════════════════════════════════════════════
#  MAIN APP
# ════════════════════════════════════════════════════════════════
else:
    ts, tb, tu = get_all_stats()
    initials   = st.session_state.username[:2].upper()
    cur        = st.session_state.page
    mode_icon  = "☀️" if st.session_state.dark_mode else "🌙"

    # ── FIXED TOP NAVBAR (HTML) ───────────────────────────────────
    # Build as string concatenation to avoid f-string / quote conflicts
    a_analyzer = "active" if cur == "analyzer" else ""
    a_chat     = "active" if cur == "chat"     else ""
    a_history  = "active" if cur == "history"  else ""

    navbar_html = (
        '<div class="navbar">'
            '<div class="navbar-brand">&#9889; CodeScan AI</div>'
            '<div class="navbar-links">'
                f'<span class="nav-pill {a_analyzer}">&#9889; Analyzer</span>'
                f'<span class="nav-pill {a_chat}">&#129302; AI Chat</span>'
                f'<span class="nav-pill {a_history}">&#128336; History</span>'
            '</div>'
            '<div class="navbar-right">'
                '<div class="nav-stats">'
                    f'<div class="nav-stat"><span class="nav-stat-val">{tu}</span><span class="nav-stat-lbl">Users</span></div>'
                    f'<div class="nav-stat"><span class="nav-stat-val">{ts}</span><span class="nav-stat-lbl">Scans</span></div>'
                    f'<div class="nav-stat"><span class="nav-stat-val">{tb}</span><span class="nav-stat-lbl">Bugs</span></div>'
                '</div>'
                f'<div class="nav-user"><div class="nav-avatar">{initials}</div>{st.session_state.username}</div>'
            '</div>'
        '</div>'
    )
    st.markdown(navbar_html, unsafe_allow_html=True)

    # ── FUNCTIONAL NAV BUTTONS (Streamlit) ───────────────────────
    n1, n2, n3, n4, n5, n6 = st.columns([2,1,1,1,1,1])
    with n2:
        if st.button("⚡ Analyzer", key="nb_a"):
            st.session_state.page = "analyzer"; st.rerun()
    with n3:
        if st.button("🤖 AI Chat",  key="nb_c"):
            st.session_state.page = "chat";     st.rerun()
    with n4:
        if st.button("🕐 History",  key="nb_h"):
            st.session_state.page = "history";  st.rerun()
    with n5:
        if st.button(f"{mode_icon} Mode", key="nb_m"):
            st.session_state.dark_mode = not st.session_state.dark_mode; st.rerun()
    with n6:
        if st.button("🚪 Logout",   key="nb_l"):
            for k in defaults: st.session_state[k] = defaults[k]
            st.rerun()

    # Style the Streamlit button row to look minimal
    st.markdown("""
    <style>
    div[data-testid="stHorizontalBlock"]:nth-of-type(1) .stButton button {
        background: transparent !important;
        border: 1px solid transparent !important;
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        padding: 6px 12px !important;
        border-radius: 20px !important;
        box-shadow: none !important;
        width: auto !important;
    }
    div[data-testid="stHorizontalBlock"]:nth-of-type(1) .stButton button:hover {
        background: #111827 !important;
        color: #a78bfa !important;
        border-color: #1f2937 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("<hr style='margin: 0 0 24px 0'>", unsafe_allow_html=True)

    # ── HERO ─────────────────────────────────────────────────────
    subtitles = {
        "analyzer": "Paste or upload your code for instant AI analysis",
        "chat":     "Ask the AI anything about your code or bugs",
        "history":  "Track your coding improvement over time",
    }
    st.markdown(
        '<div class="hero">'
        '<h1>&#9889; CodeScan AI</h1>'
        f'<p>{subtitles.get(cur, "")}</p>'
        '</div>',
        unsafe_allow_html=True
    )

    # ════════════════════════════════════════════════════════════
    #  PAGE: ANALYZER
    # ════════════════════════════════════════════════════════════
    if cur == "analyzer":

        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown('<div class="section-title">Language</div>', unsafe_allow_html=True)
            language = st.selectbox("", ["Python 🐍", "Java ☕"], label_visibility="collapsed")
        with col2:
            st.markdown('<div class="section-title">Upload File (optional)</div>', unsafe_allow_html=True)
            ext   = ".py" if "Python" in language else ".java"
            ufile = st.file_uploader(f"Drop a {ext} file", type=["py","java"],
                                     label_visibility="collapsed")

        st.markdown('<div class="section-title">Paste or Edit Code</div>', unsafe_allow_html=True)
        default_code = ""
        if ufile:
            default_code = ufile.read().decode("utf-8")
            st.success(f"✅ Loaded: {ufile.name}")

        code = st.text_area("", value=default_code, height=280,
                            placeholder="Paste your code here or upload a file above...",
                            label_visibility="collapsed")

        if st.button("⚡  Analyze Code Now", key="analyze_btn"):
            if not code.strip():
                st.warning("Please paste or upload some code first!")
            else:
                lines        = code.split("\n")
                active_lines = len([l for l in lines if l.strip()])
                lang_label   = "Python" if "Python" in language else "Java"

                bugs, suggestions = (analyze_python(lines) if lang_label == "Python"
                                     else analyze_java(lines))

                cx_score, cx_label, cx_color = calculate_complexity(lines)
                high   = sum(1 for _,_,s,_ in bugs if s=="High")
                medium = sum(1 for _,_,s,_ in bugs if s=="Medium")
                low    = sum(1 for _,_,s,_ in bugs if s=="Low")
                risk_score    = min(100, high*30 + medium*15 + low*5)
                quality_score = max(0, 100 - risk_score)

                save_scan(st.session_state.username, lang_label, active_lines,
                          len(bugs), quality_score, risk_score, cx_label)
                st.session_state.last_code       = code
                st.session_state.last_bugs       = bugs
                st.session_state.last_fixed_code = ""

                # ── Metrics ──────────────────────────────────────
                st.markdown('<div class="section-title">Results</div>', unsafe_allow_html=True)
                c1,c2,c3,c4,c5 = st.columns(5)
                for col, val, label, clr in [
                    (c1, active_lines,        "Lines",      "#a78bfa"),
                    (c2, len(bugs),           "Issues",     "#a78bfa"),
                    (c3, f"{quality_score}%", "Quality",    "#a78bfa"),
                    (c4, f"{risk_score}%",    "Risk",       "#a78bfa"),
                    (c5, cx_label,            "Complexity", cx_color),
                ]:
                    with col:
                        st.markdown(
                            '<div class="metric-card">'
                            f'<div class="metric-value" style="color:{clr}">{val}</div>'
                            f'<div class="metric-label">{label}</div>'
                            '</div>',
                            unsafe_allow_html=True
                        )

                st.markdown("<br>", unsafe_allow_html=True)
                if quality_score >= 80:   st.success("✅ Low Risk — Clean, well-written code!")
                elif quality_score >= 50: st.warning("⚠️ Medium Risk — Some issues need attention")
                else:                     st.error("🚨 High Risk — Serious issues detected!")

                # ── Issues + Fixes ────────────────────────────────
                il, ir = st.columns(2)
                with il:
                    st.markdown('<div class="section-title">Issues Detected</div>', unsafe_allow_html=True)
                    if bugs:
                        for ln, issue, sev, icon in bugs:
                            st.markdown(
                                '<div class="issue-row">'
                                f'{icon} <strong>Line {ln}</strong>&nbsp;'
                                f'<span class="badge-{sev.lower()}">{sev}</span><br>'
                                f'<span style="color:#94a3b8">{issue}</span>'
                                '</div>',
                                unsafe_allow_html=True
                            )
                    else:
                        st.success("🎉 No issues found!")

                with ir:
                    st.markdown('<div class="section-title">How to Fix</div>', unsafe_allow_html=True)
                    if suggestions:
                        for ln, fix in suggestions:
                            st.markdown(
                                '<div class="fix-row">'
                                f'&#128161; <strong>Line {ln}:</strong><br>'
                                f'<span style="color:#94a3b8">{fix}</span>'
                                '</div>',
                                unsafe_allow_html=True
                            )
                    else:
                        st.success("Nothing to fix — great code!")

                # ── Auto Fixer ────────────────────────────────────
                st.markdown('<div class="section-title">&#128295; Auto Code Fixer</div>', unsafe_allow_html=True)
                if st.button("✨  Fix My Code with AI", key="fix_btn"):
                    with st.spinner("AI is fixing your code..."):
                        prompt = (f"Fix all bugs in this {lang_label} code. "
                                  f"Return ONLY the corrected code, no explanation.\n"
                                  f"Bugs: {[i for _,i,_,_ in bugs]}\nCode:\n{code}")
                        st.session_state.last_fixed_code = ask_groq(prompt)

                if st.session_state.last_fixed_code:
                    st.markdown('<div class="section-title">&#128256; Before &amp; After</div>', unsafe_allow_html=True)
                    bc, ac = st.columns(2)
                    with bc:
                        st.markdown("**🔴 Original Code**")
                        st.code(st.session_state.last_code, language=lang_label.lower())
                    with ac:
                        st.markdown("**✅ Fixed Code**")
                        st.code(st.session_state.last_fixed_code, language=lang_label.lower())
                    st.download_button("⬇️ Download Fixed Code",
                                       data=st.session_state.last_fixed_code,
                                       file_name=f"fixed_code{ext}", mime="text/plain")

                # ── Charts ────────────────────────────────────────
                st.markdown('<div class="section-title">&#128200; Visual Analysis</div>', unsafe_allow_html=True)
                ch1, ch2 = st.columns(2)
                bg_c = "#111827" if st.session_state.dark_mode else "#ffffff"
                tc   = "#e2e8f0" if st.session_state.dark_mode else "#0f172a"

                with ch1:
                    fig, ax = plt.subplots(figsize=(5,3))
                    fig.patch.set_facecolor(bg_c); ax.set_facecolor(bg_c)
                    ax.barh(["Quality","Risk"], [quality_score, risk_score],
                            color=["#34d399","#f87171"], height=0.45)
                    ax.set_xlim(0,100); ax.tick_params(colors=tc)
                    for sp in ax.spines.values(): sp.set_color("#1f2937")
                    ax.set_title("Quality vs Risk", color="#a78bfa", fontweight="bold")
                    for i,v in enumerate([quality_score, risk_score]):
                        ax.text(v+1, i, f"{v}%", va="center", color=tc, fontweight="bold", fontsize=9)
                    st.pyplot(fig)

                with ch2:
                    if bugs:
                        fig2, ax2 = plt.subplots(figsize=(5,3))
                        fig2.patch.set_facecolor(bg_c)
                        counts = {k:v for k,v in {"High":high,"Medium":medium,"Low":low}.items() if v>0}
                        ax2.pie(counts.values(), labels=counts.keys(),
                                colors=["#f87171","#fb923c","#a3e635"],
                                autopct="%1.0f%%", textprops={"color":tc})
                        ax2.set_title("Severity Breakdown", color="#a78bfa", fontweight="bold")
                        st.pyplot(fig2)
                    else:
                        st.success("🎉 No bugs to chart!")

                # ── Summary ───────────────────────────────────────
                st.markdown('<div class="section-title">&#128203; Summary Report</div>', unsafe_allow_html=True)
                st.markdown(f"""
                | Detail | Value |
                |---|---|
                | Language | {lang_label} |
                | Lines analyzed | {active_lines} |
                | Total issues | {len(bugs)} |
                | High severity | {high} |
                | Medium severity | {medium} |
                | Low severity | {low} |
                | Complexity | {cx_label} |
                | Quality score | {quality_score}% |
                | Risk score | {risk_score}% |
                | Scanned at | {datetime.now().strftime('%d %b %Y — %H:%M:%S')} |
                """)

    # ════════════════════════════════════════════════════════════
    #  PAGE: AI CHAT
    # ════════════════════════════════════════════════════════════
    elif cur == "chat":

        st.markdown("<span style='color:#94a3b8;font-size:0.9rem'>Ask anything about your code, bugs, or programming concepts.</span>",
                    unsafe_allow_html=True)

        for msg in st.session_state.chat_history:
            cls = "chat-msg-user" if msg["role"]=="user" else "chat-msg-ai"
            ico = "&#128100;" if msg["role"]=="user" else "&#129302;"
            st.markdown(
                f'<div class="{cls}">{ico} {msg["content"]}</div>',
                unsafe_allow_html=True
            )

        def send(q):
            with st.spinner("AI is thinking..."):
                r = ask_groq(q)
            st.session_state.chat_history += [
                {"role":"user","content":q},
                {"role":"assistant","content":r}
            ]
            st.rerun()

        st.markdown("---")
        st.markdown("**&#9889; Quick Questions:**")
        qc1, qc2, qc3 = st.columns(3)
        with qc1:
            if st.button("❓ Explain my last bugs", key="q1"):
                if st.session_state.last_bugs:
                    send(f"Explain simply: {[i for _,i,_,_ in st.session_state.last_bugs]}")
                else:
                    st.warning("Scan code first in the Analyzer!")
        with qc2:
            if st.button("💡 Tips for cleaner code", key="q2"):
                send("Give me 5 practical tips for writing cleaner Python or Java code")
        with qc3:
            if st.button("🔐 Security best practices", key="q3"):
                send("Top 5 security best practices for Python and Java?")

        st.markdown("---")
        user_input = st.text_input("&#128172; Ask the AI anything...", key="chat_input")
        sc1, sc2   = st.columns([5,1])
        with sc1:
            if st.button("Send →", key="send_btn"):
                if user_input.strip(): send(user_input)
                else: st.warning("Type something first!")
        with sc2:
            if st.button("🗑️ Clear", key="clear_chat"):
                st.session_state.chat_history = []; st.rerun()

    # ════════════════════════════════════════════════════════════
    #  PAGE: HISTORY
    # ════════════════════════════════════════════════════════════
    elif cur == "history":

        scans = get_user_scans(st.session_state.username)
        if not scans:
            st.info("No scans yet — go to the Analyzer and scan some code!")
        else:
            total   = len(scans)
            avg_q   = round(sum(s[5] for s in scans) / total)
            total_b = sum(s[4] for s in scans)

            h1, h2, h3 = st.columns(3)
            for col, val, label in [
                (h1, total,       "Total Scans"),
                (h2, f"{avg_q}%", "Avg Quality"),
                (h3, total_b,     "Total Bugs Found"),
            ]:
                with col:
                    st.markdown(
                        '<div class="metric-card">'
                        f'<div class="metric-value">{val}</div>'
                        f'<div class="metric-label">{label}</div>'
                        '</div>',
                        unsafe_allow_html=True
                    )

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="section-title">All Scans</div>', unsafe_allow_html=True)

            for s in scans:
                sat = s[8] if len(s)>8 else "N/A"
                cpx = s[7] if len(s)>7 else "N/A"
                qc  = "#34d399" if s[5]>=80 else "#fb923c" if s[5]>=50 else "#f87171"
                st.markdown(
                    '<div class="history-row">'
                    '<div style="display:flex;justify-content:space-between;align-items:center">'
                    f'<span style="font-weight:600;font-size:0.95rem">{s[2]}</span>'
                    f'<span style="color:{qc};font-weight:700;font-size:1.1rem">{s[5]}%</span>'
                    '</div>'
                    f'<div style="color:#64748b;font-size:0.78rem;margin-top:2px">{sat}</div>'
                    '<div style="color:#94a3b8;font-size:0.84rem;margin-top:8px">'
                    f'&#128196; {s[3]} lines &nbsp;&middot;&nbsp; &#128027; {s[4]} bugs &nbsp;&middot;&nbsp; &#129504; {cpx}'
                    '</div>'
                    '</div>',
                    unsafe_allow_html=True
                )

            if len(scans) >= 2:
                st.markdown('<div class="section-title">&#128200; Quality Trend</div>', unsafe_allow_html=True)
                bg_c = "#111827" if st.session_state.dark_mode else "#ffffff"
                tc   = "#e2e8f0" if st.session_state.dark_mode else "#0f172a"
                fig, ax = plt.subplots(figsize=(10,3))
                fig.patch.set_facecolor(bg_c); ax.set_facecolor(bg_c)
                scores = [s[5] for s in reversed(scans)]
                ax.plot(scores, color="#a78bfa", linewidth=2.5,
                        marker="o", markerfacecolor="#6366f1", markersize=7)
                ax.fill_between(range(len(scores)), scores, alpha=0.12, color="#a78bfa")
                ax.set_ylim(0,100)
                ax.set_ylabel("Quality %", color=tc)
                ax.set_xlabel("Scan number", color=tc)
                ax.tick_params(colors=tc)
                for sp in ax.spines.values(): sp.set_color("#1f2937")
                ax.set_title("Your Code Quality Over Time", color="#a78bfa", fontweight="bold")
                st.pyplot(fig)
