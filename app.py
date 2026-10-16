
import streamlit as st
import pandas as pd
import hashlib
import re
import io
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from url_validation import normalize_and_parse_url
from collections import Counter

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
:root {
    --cs-bg: #07111f;
    --cs-panel: #0e1b2d;
    --cs-panel-2: #12243a;
    --cs-border: #203954;
    --cs-cyan: #43d9ff;
    --cs-blue: #4f8cff;
    --cs-text: #edf5ff;
    --cs-muted: #9db0c8;
}
.stApp {
    background: radial-gradient(ellipse at 12% 0%, #122d4a 0%, transparent 38%),
                linear-gradient(145deg, #07111f 0%, #0a1424 52%, #0d1b2e 100%);
    color: var(--cs-text);
}
[data-testid="stHeader"] { background: rgba(7, 17, 31, 0.82); }
[data-testid="stAppViewContainer"] .main .block-container {
    max-width: 1450px;
    padding-top: 2.1rem;
    padding-bottom: 3rem;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #081525 0%, #0b1b2e 100%);
    border-right: 1px solid #1c3550;
}
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 { color: #edf5ff; }
[data-testid="stSidebar"] [data-testid="stRadio"] label { padding: 0.25rem 0; }
h1, h2, h3, h4 { color: #edf5ff; letter-spacing: -0.025em; }
h1 { font-weight: 800; }
p, label, [data-testid="stCaptionContainer"] { color: #aebfd4; }
[data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(18, 36, 58, 0.96), rgba(12, 27, 45, 0.96));
    border: 1px solid #254360;
    padding: 1rem 1.15rem;
    border-radius: 16px;
    box-shadow: 0 8px 26px rgba(0, 0, 0, 0.16);
}
[data-testid="stMetricLabel"] { color: #a9bfd8; font-weight: 600; }
[data-testid="stMetricValue"] { color: #f5f9ff; font-weight: 800; }
[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: #203954 !important;
    border-radius: 16px !important;
    background: rgba(13, 29, 48, 0.74);
}
div.stButton > button, div.stDownloadButton > button, [data-testid="stFormSubmitButton"] button {
    border-radius: 10px;
    border: 1px solid #2b6285;
    font-weight: 700;
    transition: all 160ms ease;
}
div.stButton > button[kind="primary"], [data-testid="stFormSubmitButton"] button[kind="primary"] {
    background: linear-gradient(100deg, #087ea4, #2563eb);
    color: white;
    border: 0;
}
div.stButton > button:hover, div.stDownloadButton > button:hover {
    border-color: #43d9ff;
    color: #ffffff;
    transform: translateY(-1px);
}
[data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea,
[data-testid="stNumberInput"] input, [data-testid="stSelectbox"] div[data-baseweb="select"] {
    background-color: #0c1b2d;
    border-color: #2a4562;
    border-radius: 10px;
}
[data-testid="stDataFrame"], [data-testid="stTable"] {
    border: 1px solid #203954;
    border-radius: 12px;
    overflow: hidden;
}
hr { border-color: #203954; }
[data-testid="stAlert"] { border-radius: 12px; }
code { color: #8be9fd; }
a { color: #6bdcff !important; }

.hero-banner {padding:1.45rem 1.6rem;border:1px solid rgba(67,217,255,.32);border-radius:20px;background:linear-gradient(115deg,rgba(8,126,164,.24),rgba(37,99,235,.13) 48%,rgba(13,29,48,.88));box-shadow:0 14px 36px rgba(0,0,0,.18);margin:.25rem 0 1.1rem 0}
.hero-eyebrow {color:#43d9ff;font-size:.74rem;letter-spacing:.14em;font-weight:800}
.hero-title {color:#f5f9ff;font-size:2.15rem;font-weight:850;letter-spacing:-.04em;margin:.25rem 0 .3rem 0}
.hero-copy {color:#b7c8dc;font-size:.98rem;line-height:1.55;margin-bottom:.6rem}
.pill {display:inline-block;padding:.25rem .65rem;border-radius:999px;border:1px solid #2a607a;background:#0b2639;color:#83e6ff;font-size:.74rem;font-weight:700;margin-right:.35rem}
.module-card-title {color:#edf5ff;font-size:1.04rem;font-weight:800;margin:.2rem 0 .35rem 0}
.module-card-copy {color:#aebfd4;font-size:.88rem;line-height:1.45;min-height:3.8rem}
.small-note {color:#8fa6c0;font-size:.78rem}

</style>
""", unsafe_allow_html=True)

if "findings" not in st.session_state:
    st.session_state.findings = []

def navigate_to(target):
    """Switch the sidebar radio selection through a Streamlit callback."""
    st.session_state.page_nav = target


def add_finding(module, severity, title, details):
    st.session_state.findings.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "module": module,
        "severity": severity,
        "title": title,
        "details": details
    })

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def investigate_url(value, check_live=False):
    """Assess URL indicators and optionally perform a bounded live HTTP(S) inspection.

    Live inspection is opt-in and only performed from the PhishProof submit action.
    It blocks non-public destinations, validates every redirect, uses timeouts, and
    reads only a small amount of page content. It is not a sandbox or malware scan.
    """
    import base64
    import ipaddress
    import os
    from urllib.parse import urlsplit

    parsed_input = normalize_and_parse_url(value)
    value = parsed_input["url"]
    result = {
        "url": value,
        "host": parsed_input["host"],
        "score": 0,
        "verdict": "Invalid input",
        "confidence": "Limited",
        "evidence": [],
        "sources": [],
        "unknowns": [],
        "recommendation": parsed_input["error"] or "Review the URL indicators and reputation results; parsing alone does not establish safety.",
        "scheme": parsed_input["scheme"],
        "path": parsed_input["path"],
        "port": parsed_input["port"],
        "explicit_port": parsed_input["explicit_port"],
        "url_valid": parsed_input["valid"],
        "website_check": {
            "performed": False,
            "status": "Not requested",
            "http_status": None,
            "final_url": None,
            "redirects": [],
            "content_type": None,
            "page_title": None,
            "security_headers": {},
            "findings": [],
            "error": None,
        },
    }
    if not parsed_input["valid"]:
        result["evidence"].append(parsed_input["error"])
        return result

    # Parse the already-validated, normalized value for query/path heuristics.
    parsed = urlsplit(value)
    host = parsed_input["host"]
    result["query_present"] = bool(parsed.query)

    if check_live:
        import ipaddress
        import socket
        import html as html_lib
        from urllib.parse import urljoin

        site_check = result["website_check"]
        site_check["performed"] = True

        def public_destination(candidate_url):
            """Reject local/private destinations before making any outbound request."""
            try:
                candidate = urlsplit(candidate_url)
                candidate_host = candidate.hostname
                if candidate.scheme.lower() not in ("http", "https") or not candidate_host:
                    return False, "Only HTTP and HTTPS redirect destinations are allowed."
                if candidate.username is not None or candidate.password is not None:
                    return False, "URLs containing embedded username/password credentials are not fetched."
                try:
                    ip = ipaddress.ip_address(candidate_host)
                    addresses = [ip]
                except ValueError:
                    try:
                        addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(candidate_host, candidate.port or (443 if candidate.scheme == "https" else 80), type=socket.SOCK_STREAM)]
                    except Exception:
                        return False, "Hostname could not be resolved to an IP address."
                if not addresses:
                    return False, "Hostname did not resolve to an IP address."
                if any(not address.is_global for address in addresses):
                    return False, "Live inspection blocked: the hostname resolves to a private, local, or non-public IP address."
                return True, ""
            except Exception:
                return False, "Destination could not be validated for live inspection."

        try:
            import requests
            current_url = value
            visited = []
            max_redirects = 5
            response = None
            for hop in range(max_redirects + 1):
                allowed, reason = public_destination(current_url)
                if not allowed:
                    site_check["status"] = "Blocked"
                    site_check["error"] = reason
                    break
                response = requests.get(
                    current_url,
                    timeout=(4, 7),
                    allow_redirects=False,
                    stream=True,
                    headers={"User-Agent": "CyberShieldAI-URL-Inspector/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"},
                    verify=True,
                )
                site_check["http_status"] = response.status_code
                site_check["content_type"] = response.headers.get("Content-Type", "unknown")
                if response.is_redirect or response.is_permanent_redirect or response.status_code in (300, 301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    response.close()
                    if not location:
                        site_check["status"] = "Redirect response without a Location header"
                        break
                    next_url = urljoin(current_url, location)
                    visited.append({"from": current_url, "to": next_url, "status": site_check["http_status"]})
                    if hop >= max_redirects:
                        site_check["status"] = "Redirect limit reached"
                        site_check["error"] = "Stopped after five redirects."
                        break
                    current_url = next_url
                    continue

                site_check["final_url"] = current_url
                site_check["status"] = "HTTP response received"
                site_check["security_headers"] = {
                    "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Missing"),
                    "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Missing"),
                    "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Missing"),
                    "X-Frame-Options": response.headers.get("X-Frame-Options", "Missing"),
                    "Referrer-Policy": response.headers.get("Referrer-Policy", "Missing"),
                }
                if current_url.lower().startswith("https://") and not site_check["security_headers"]["Strict-Transport-Security"] != "Missing":
                    site_check["findings"].append("HTTPS response did not include a Strict-Transport-Security header.")
                if response.status_code >= 400:
                    site_check["findings"].append(f"Website returned HTTP {response.status_code}; this may indicate an error page or access restriction, not maliciousness by itself.")
                if current_url.lower().startswith("http://"):
                    site_check["findings"].append("The final page uses unencrypted HTTP.")
                if any(site_check["security_headers"][name] == "Missing" for name in ("Content-Security-Policy", "X-Content-Type-Options")):
                    site_check["findings"].append("One or more recommended browser security headers are missing; this is a configuration observation, not proof of a malicious site.")

                # Read at most 100 KiB to extract a title and basic page clues.
                content_type = site_check["content_type"].lower()
                if "text/html" in content_type or "application/xhtml+xml" in content_type:
                    chunks = []
                    total = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = 102400 - total
                        if remaining <= 0:
                            break
                        chunk = chunk[:remaining]
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= 102400:
                            break
                    encoding = response.encoding or "utf-8"
                    page_text = b"".join(chunks).decode(encoding, errors="replace")
                    title_match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", page_text, re.I | re.S)
                    if title_match:
                        site_check["page_title"] = html_lib.unescape(re.sub(r"<[^>]+>", "", title_match.group(1))).strip()[:200]
                    if re.search(r"<input\b[^>]*type\s*=\s*['\"]?password", page_text, re.I):
                        site_check["findings"].append("The page contains a password input. Verify the domain carefully before entering credentials.")
                    if current_url.lower().startswith("https://") and re.search(r"(?:src|href)\s*=\s*['\"]http://", page_text, re.I):
                        site_check["findings"].append("The HTML sample contains references to HTTP resources on an HTTPS page (possible mixed content).")
                    site_check["bytes_inspected"] = total
                response.close()
                break
            site_check["redirects"] = visited
            if response is None and not site_check["error"]:
                site_check["status"] = "No response received"
        except requests.exceptions.SSLError:
            site_check["status"] = "TLS certificate verification failed"
            site_check["error"] = "The HTTPS certificate could not be verified. Do not ignore browser certificate warnings."
            site_check["findings"].append("TLS certificate verification failed.")
        except requests.exceptions.Timeout:
            site_check["status"] = "Timed out"
            site_check["error"] = "The website did not respond within the configured time limit."
        except requests.exceptions.RequestException as exc:
            site_check["status"] = "Request failed"
            site_check["error"] = f"Could not fetch the website ({type(exc).__name__})."
        except Exception as exc:
            site_check["status"] = "Inspection failed"
            site_check["error"] = f"Live inspection could not complete ({type(exc).__name__})."
    score = 0
    strong_reputation_match = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    def flag(points, message):
        nonlocal score
        score += points
        result["evidence"].append(message)

    host_labels = host.split(".")
    full_text = (parsed.path + "?" + parsed.query + "#" + parsed.fragment).lower()
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly"}
    redirect_keys = {"url", "target", "redirect", "redirect_url", "redirect_uri", "return", "returnto", "next", "continue", "dest", "destination", "to"}
    try:
        from urllib.parse import parse_qsl, unquote
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        decoded_path_query = unquote(parsed.path + "?" + parsed.query)
    except Exception:
        query_pairs = []
        decoded_path_query = parsed.path + "?" + parsed.query

    if parsed.username is not None or parsed.password is not None:
        flag(25, "User information appears before the hostname and may disguise the actual destination.")
    if parsed.scheme.lower() != "https":
        flag(10, "The URL uses HTTP rather than HTTPS; the connection is not encrypted in transit.")
    if is_ip:
        flag(15, "The destination is an IP address instead of a domain; this is a risk signal, not proof of abuse.")
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                result["evidence"].append("The IP address is private, loopback, link-local, or otherwise non-public; it may only resolve inside a local network.")
        except ValueError:
            pass
    if any(label.startswith("xn--") for label in host_labels):
        flag(20, "The hostname contains a punycode label; check for internationalized lookalike characters.")
    if len(value) > 200:
        flag(8, "The URL is unusually long, which can make the true destination harder to inspect.")
    if len(host_labels) >= 5 and not is_ip:
        flag(8, "The hostname has many subdomain levels; inspect the registered domain, not just the leftmost name.")
    if parsed.port not in (None, 80, 443):
        flag(8, f"The URL uses a non-standard web port ({parsed.port}).")
    if host in shorteners:
        flag(20, "The domain is a URL-shortening service, so the final destination is hidden from this static check; treat it as needing review.")
    if re.search(r"(?:login|verify|account|password|wallet|payment|signin|auth|reset)", decoded_path_query, re.I):
        flag(6, "The path or query mentions account, sign-in, or payment actions; this is a weak signal on its own.")
    if re.search(r"(?:%[0-9a-f]{2}){3,}", parsed.path + parsed.query, re.I):
        flag(6, "The URL contains a run of percent-encoded characters; decode and inspect it carefully.")
    if re.search(r"(?:\.exe|\.msi|\.scr|\.bat|\.cmd|\.ps1|\.apk|\.dmg)(?:$|[?#])", parsed.path, re.I):
        flag(12, "The path appears to end in an executable or installable file type; only download from a trusted source.")
    if any(key.lower() in redirect_keys and re.match(r"https?%?3a", val, re.I) for key, val in query_pairs):
        flag(10, "A redirect-like query parameter contains a URL; inspect the eventual destination before trusting it.")
    if "@" in parsed.netloc and parsed.username is None:
        flag(8, "The hostname section contains an @ character; verify how the URL is parsed.")

    # Brand lookalike heuristics are clues only; they do not verify ownership.
    brand_domains = {
        "google": ("google.com", "google.co.in"),
        "microsoft": ("microsoft.com", "live.com", "office.com"),
        "apple": ("apple.com", "icloud.com"),
        "paypal": ("paypal.com",),
        "amazon": ("amazon.com", "amazon.in"),
        "instagram": ("instagram.com",),
        "facebook": ("facebook.com",),
        "whatsapp": ("whatsapp.com",),
    }
    for brand, official_domains in brand_domains.items():
        if brand in host and not any(host == d or host.endswith("." + d) for d in official_domains):
            flag(14, f"The hostname contains the brand name '{brand}' but does not match the common official domains in this simple check.")
            break
    if re.search(r"(?:^|[-.])(?:secure|verify|account|support|login|update)[-.]", host):
        flag(5, "The hostname uses security/account-style wording; attackers can use these words too, so verify the domain owner.")

    # Optional reputation lookups. API keys should be stored in Streamlit Secrets,
    # not committed to source control. Neither provider causes the URL to be opened.
    def get_secret(name):
        value_from_env = os.getenv(name)
        if value_from_env:
            return value_from_env
        try:
            return st.secrets.get(name, "")
        except Exception:
            return ""

    safe_key = get_secret("GOOGLE_SAFE_BROWSING_API_KEY")
    vt_key = get_secret("VIRUSTOTAL_API_KEY")
    try:
        import requests
    except ImportError:
        requests = None

    if safe_key and requests:
        try:
            response = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": safe_key},
                json={
                    "client": {"clientId": "cybershield-ai", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": value}],
                    },
                },
                timeout=6,
            )
            if response.ok:
                matches = response.json().get("matches", [])
                if matches:
                    strong_reputation_match = True
                    flag(75, f"Google Safe Browsing reported a threat match ({len(matches)} match(es)).")
                    result["sources"].append("Google Safe Browsing: threat match")
                else:
                    result["sources"].append("Google Safe Browsing: no match returned")
            else:
                result["unknowns"].append(f"Google Safe Browsing lookup returned HTTP {response.status_code}.")
        except Exception as exc:
            result["unknowns"].append(f"Google Safe Browsing lookup could not be completed ({type(exc).__name__}).")
    else:
        result["unknowns"].append("Google Safe Browsing was not checked (API key or requests package not configured).")

    if vt_key and requests:
        try:
            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_key},
                timeout=6,
            )
            if response.ok:
                attrs = response.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                if malicious:
                    strong_reputation_match = True
                    flag(min(80, 35 + malicious * 5), f"VirusTotal's latest report lists {malicious} malicious detection(s) and {suspicious} suspicious detection(s).")
                elif suspicious:
                    flag(min(35, 10 + suspicious * 5), f"VirusTotal's latest report lists {suspicious} suspicious detection(s).")
                result["sources"].append(f"VirusTotal: {malicious} malicious, {suspicious} suspicious, {harmless} harmless detections in the available report")
            elif response.status_code == 404:
                result["unknowns"].append("VirusTotal has no existing URL report. This does not mean the URL is safe; the app did not submit or open it.")
            else:
                result["unknowns"].append(f"VirusTotal lookup returned HTTP {response.status_code}.")
        except Exception as exc:
            result["unknowns"].append(f"VirusTotal lookup could not be completed ({type(exc).__name__}).")
    else:
        result["unknowns"].append("VirusTotal was not checked (API key or requests package not configured).")

    result["score"] = min(100, score)
    if score >= 75:
        result["verdict"] = "High risk"
        result["confidence"] = "Reputation match found" if strong_reputation_match else "Heuristic only"
        result["recommendation"] = "Do not open the link or enter information. Verify it through the organization's official website or a trusted security team."
    elif score >= 40:
        result["verdict"] = "Suspicious"
        result["confidence"] = "Moderate; evidence is incomplete"
        result["recommendation"] = "Avoid interacting with the link until its destination and reputation are independently verified."
    elif score >= 20:
        result["verdict"] = "Needs review"
        result["confidence"] = "Limited; heuristic indicators"
        result["recommendation"] = "Check the registered domain and reputation using trusted tools before opening the link."
    else:
        result["verdict"] = "No strong indicators observed"
        result["confidence"] = "Limited; not a safety certification"
        result["recommendation"] = "No configured indicators were strong enough to raise the score. This does not prove the URL is safe."
    if not result["evidence"]:
        result["evidence"].append("No local URL-pattern indicators matched.")
    return result


def scan_prompt(text):
    import re

    rules = [
        {
            "category": "Instruction override",
            "severity": "High",
            "pattern": (
                r"\b(ignore|disregard|override|forget)\b.{0,60}"
                r"\b(previous|prior|above|all)\b.{0,40}"
                r"\b(instructions?|rules?|prompts?)\b"
            ),
            "explanation": "Text may be attempting to override earlier instructions.",
            "recommendation": "Keep system instructions separate and do not follow untrusted overrides."
        },
        {
            "category": "Hidden prompt extraction",
            "severity": "High",
            "pattern": (
                r"\b(reveal|print|show|disclose|repeat|leak)\b.{0,60}"
                r"\b(system prompt|hidden instructions|developer message|secret prompt)\b"
            ),
            "explanation": "Text appears to request hidden instructions or internal prompts.",
            "recommendation": "Do not disclose confidential system or developer instructions."
        },
        {
            "category": "Safety bypass attempt",
            "severity": "High",
            "pattern": (
                r"\b(bypass|disable|evade|ignore)\b.{0,50}"
                r"\b(safety|guardrails?|security restrictions?|filters?)\b"
            ),
            "explanation": "Text may be asking to bypass safety controls.",
            "recommendation": "Preserve safety checks and evaluate the request under your policy."
        },
        {
            "category": "Role or authority manipulation",
            "severity": "Medium",
            "pattern": (
                r"\b(act as|pretend to be|you are now)\b.{0,60}"
                r"\b(unrestricted|no rules|administrator|system|developer)\b"
            ),
            "explanation": "Text may be trying to change the model's role or authority.",
            "recommendation": "Do not treat user text as higher-priority system instructions."
        },
        {
            "category": "Email address",
            "severity": "Low",
            "pattern": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "explanation": "An email-address-shaped string was found.",
            "recommendation": "Check whether this personal information needs to be included."
        },
        {
            "category": "Possible credential",
            "severity": "High",
            "pattern": (
                r"\b(api[_ -]?key|access[_ -]?token|client[_ -]?secret|"
                r"password|passwd|secret[_ -]?key)\b\s*[:=]\s*\S+"
            ),
            "explanation": "A possible credential assignment was detected.",
            "recommendation": "Remove secrets from the text and rotate exposed credentials if genuine."
        },
        {
            "category": "Possible payment-card number",
            "severity": "Medium",
            "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
            "explanation": "A long digit sequence may represent sensitive payment information.",
            "recommendation": "Verify locally and redact payment information where unnecessary."
        }
    ]

    findings = []
    for rule in rules:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            findings.append({
                "category": rule["category"],
                "severity": rule["severity"],
                "explanation": rule["explanation"],
                "recommendation": rule["recommendation"]
            })

    return findings

def make_sample_logs():
    return pd.DataFrame([
        {"timestamp": "2026-10-15 09:01", "source_ip": "192.0.2.10",
         "username": "student1", "event": "login", "status": "success",
         "bytes_out": 1200},
        {"timestamp": "2026-10-15 09:02", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:03", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:04", "source_ip": "198.51.100.8",
         "username": "admin", "event": "login", "status": "failed",
         "bytes_out": 100},
        {"timestamp": "2026-10-15 09:05", "source_ip": "192.0.2.22",
         "username": "student2", "event": "upload", "status": "success",
         "bytes_out": 15000000}
    ])


def analyze_logs(df):
    import ipaddress

    alerts = []
    # Normalize column names before validation so CSV headers such as
    # Source_IP or STATUS are accepted consistently.
    data = df.copy()
    data.columns = [str(c).strip().lower() for c in data.columns]

    required = {"source_ip", "status"}
    missing = required - set(data.columns)

    if missing:
        return [{
            "severity": "High",
            "rule": "Schema validation",
            "source_ip": "",
            "evidence": "Missing required columns: " +
                        ", ".join(sorted(missing)),
            "recommendation": "Add the required columns and upload again."
        }]

    # Validate source IP addresses where possible.
    invalid_ips = []
    for idx, raw_ip in data["source_ip"].items():
        try:
            ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            invalid_ips.append((idx, str(raw_ip)))

    for idx, raw_ip in invalid_ips:
        alerts.append({
            "severity": "Low",
            "rule": "Invalid source IP",
            "source_ip": raw_ip,
            "evidence": f"Row {idx + 1} has an invalid IP value.",
            "recommendation": "Check the source_ip field in the original log."
        })

    # Repeated failed logins from one source IP.
    statuses = data["status"].fillna("").astype(str).str.strip().str.lower()
    failed = data[statuses.isin(["failed", "failure", "denied"])]

    failed_counts = failed["source_ip"].fillna("UNKNOWN").astype(str).value_counts()

    for ip, count in failed_counts.items():
        if count >= 3:
            alerts.append({
                "severity": "High" if count >= 5 else "Medium",
                "rule": "Repeated failed logins",
                "source_ip": ip,
                "evidence": f"{count} failed events were found for this source.",
                "recommendation": (
                    "Review authentication logs and verify whether the "
                    "activity belongs to an authorized user."
                )
            })

    # Large outbound transfers; threshold is configurable in the UI.
    if "bytes_out" in data.columns:
        sizes = pd.to_numeric(data["bytes_out"], errors="coerce")

        invalid_sizes = sizes.isna() & data["bytes_out"].notna()
        if invalid_sizes.any():
            alerts.append({
                "severity": "Low",
                "rule": "Invalid transfer-size values",
                "source_ip": "",
                "evidence": f"{int(invalid_sizes.sum())} rows have non-numeric bytes_out values.",
                "recommendation": "Correct the bytes_out column before relying on transfer alerts."
            })

        threshold = 10_000_000
        for idx in data.index[sizes >= threshold]:
            alerts.append({
                "severity": "Medium",
                "rule": "Large outbound transfer",
                "source_ip": str(data.loc[idx, "source_ip"]),
                "evidence": f"Row {idx + 1}: {sizes.loc[idx]:,.0f} bytes sent.",
                "recommendation": (
                    "Compare the transfer with normal activity and approved "
                    "data-transfer policies."
                )
            })

    # Several distinct usernames failing from the same IP.
    if "username" in data.columns:
        failed_with_users = failed.copy()
        failed_with_users["username"] = (
            failed_with_users["username"].fillna("").astype(str).str.strip()
        )
        for ip, group in failed_with_users.groupby("source_ip"):
            users = sorted({
                u for u in group["username"].tolist() if u
            })
            if len(users) >= 3:
                alerts.append({
                    "severity": "High",
                    "rule": "Multiple-account login failures",
                    "source_ip": str(ip),
                    "evidence": f"Failed attempts involved {len(users)} usernames.",
                    "recommendation": (
                        "Review for password spraying and confirm whether "
                        "the source is an approved scanner or administrator."
                    )
                })

    if not alerts:
        alerts.append({
            "severity": "Info",
            "rule": "No configured rule matched",
            "source_ip": "",
            "evidence": "The analyzer did not detect activity covered by its rules.",
            "recommendation": (
                "This does not prove the logs are benign. Add relevant "
                "detection rules for your environment."
            )
        })

    return alerts


st.title("🛡️ CyberShield AI")
st.caption("SECURITY OPERATIONS PLATFORM  •  CYBERSHIELD 2K26")
st.info(
    "Prototype only: checks are rule-based, not a trained AI or a substitute "
    "for professional security tools. Use sample or authorized data."
)

PAGES = [
    "Dashboard", "VisionGuard", "PhishProof",
    "PromptFence AI", "NetSage", "SOC Copilot"
]
if "page_nav" not in st.session_state:
    st.session_state.page_nav = "Dashboard"

with st.sidebar:
    st.markdown("## 🛡️ CyberShield")
    st.caption("SECURITY ANALYSIS WORKSPACE")
    page = st.radio("NAVIGATION", PAGES, key="page_nav")
    st.divider()
    st.markdown("**Analysis modules**")
    st.caption("VisionGuard · PhishProof · PromptFence AI · NetSage · SOC Copilot")
    st.divider()
    st.caption("CyberShield 2K26 • MVP")
    st.caption("Session-based results • No live monitoring implied")


if page == "Dashboard":
    findings = list(st.session_state.findings)
    high = sum(str(x.get("severity", "")).lower() == "high" for x in findings)
    medium = sum(str(x.get("severity", "")).lower() == "medium" for x in findings)
    low = sum(str(x.get("severity", "")).lower() == "low" for x in findings)
    info = sum(str(x.get("severity", "")).lower() in ("info", "informational") for x in findings)

    st.markdown("""
    <div class="hero-banner">
      <div class="hero-eyebrow">CYBERSHIELD 2K26 / SECURITY OPERATIONS</div>
      <div class="hero-title">CyberShield <span style="color:#43d9ff">AI</span></div>
      <div class="hero-copy">A unified workspace for first-pass security checks, explainable indicators, and incident review.</div>
      <span class="pill">5 SECURITY MODULES</span><span class="pill">SHA-256 INTEGRITY</span><span class="pill">EXPLAINABLE FINDINGS</span>
    </div>
    """, unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with left:
        st.markdown("### Security overview")
        st.caption("A summary of findings recorded in this app session. This is not a live SOC feed.")
    with right:
        st.markdown(
            f'<div style="text-align:right;padding-top:.45rem;color:#9db0c8;font-size:.8rem;">'
            f'<span style="color:#43d9ff">●</span> SESSION ANALYTICS<br>{datetime.now().strftime("%d %b %Y · %H:%M")}</div>',
            unsafe_allow_html=True
        )

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total findings", len(findings), help="Findings recorded by modules during this app session.")
    k2.metric("High severity", high, help="Items labelled High by the current detection rules.")
    k3.metric("Medium severity", medium, help="Items labelled Medium by the current detection rules.")
    k4.metric("Low / Info", low + info, help="Lower-severity and informational findings.")

    st.markdown("### Explore security modules")
    module_data = [
        ("01", "🔎 VisionGuard", "File integrity", "SHA-256 hashes, trusted baselines, and file-change verification.", "VisionGuard"),
        ("02", "🔗 PhishProof", "URL analysis", "URL structure indicators and optional reputation checks when configured.", "PhishProof"),
        ("03", "🧠 PromptFence AI", "Text inspection", "Pattern checks for prompt-injection attempts and sensitive-data indicators.", "PromptFence AI"),
        ("04", "📊 NetSage", "Log analysis", "Rule-based review of authentication and other supported log events.", "NetSage"),
        ("05", "📝 SOC Copilot", "Incident review", "A consolidated view of recorded findings and available exports.", "SOC Copilot"),
    ]
    cols = st.columns(3)
    for idx, (number, name, category, description, target) in enumerate(module_data):
        with cols[idx % 3]:
            with st.container(border=True):
                st.caption(f"MODULE {number} · {category.upper()}")
                st.markdown(f'<div class="module-card-title">{name}</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="module-card-copy">{description}</div>', unsafe_allow_html=True)
                st.button(
                    "Open module →",
                    key=f"open_module_{number}",
                    width="stretch",
                    on_click=navigate_to,
                    args=(target,),
                )

    st.divider()
    chart_col, insight_col = st.columns([1.15, 1])
    with chart_col:
        st.markdown("### Severity distribution")
        if findings:
            severity_counts = pd.Series([str(x.get("severity", "Unknown")) for x in findings]).value_counts()
            severity_order = [x for x in ["High", "Medium", "Low", "Info", "Informational", "Unknown"] if x in severity_counts.index]
            severity_df = pd.DataFrame({
                "Severity": severity_order,
                "Findings": [int(severity_counts[x]) for x in severity_order]
            }).set_index("Severity")
            st.bar_chart(severity_df, width="stretch")
        else:
            st.info("Run a module to populate the severity chart.")
    with insight_col:
        st.markdown("### Analyst quick view")
        if findings:
            high_items = [x for x in findings if str(x.get("severity", "")).lower() == "high"]
            medium_items = [x for x in findings if str(x.get("severity", "")).lower() == "medium"]
            if high_items:
                st.error(f"{len(high_items)} high-severity finding(s) recorded. Validate the evidence first and review these before lower-priority items.")
            elif medium_items:
                st.warning(f"{len(medium_items)} medium-severity finding(s) recorded. Review the context and confirm whether the activity is expected.")
            else:
                st.success("No High-severity findings are currently recorded in this session.")
            st.markdown("**Recommended workflow**")
            st.markdown("1. Inspect the evidence and the rule that triggered.\n2. Confirm the finding using trusted context.\n3. Document the decision before taking action.")
        else:
            st.markdown("""
            <div class="small-note"><b>Get started</b><br><br>
            1. Run one or more modules from the cards above.<br>
            2. Return here to review the findings summary.<br>
            3. Open SOC Copilot to review and export recorded results.</div>
            """, unsafe_allow_html=True)

    st.divider()
    st.markdown("### Recent findings")
    if findings:
        all_df = pd.DataFrame(findings)
        filter_col1, filter_col2 = st.columns([1, 2])
        with filter_col1:
            severity_options = ["All"] + sorted(all_df["severity"].dropna().astype(str).unique().tolist())
            selected_severity = st.selectbox("Filter by severity", severity_options)
        with filter_col2:
            search_term = st.text_input("Search findings", placeholder="Search module, title, or evidence…")

        view_df = all_df.copy()
        if selected_severity != "All":
            view_df = view_df[view_df["severity"].astype(str) == selected_severity]
        if search_term.strip():
            mask = view_df.astype(str).apply(lambda col: col.str.contains(search_term.strip(), case=False, na=False)).any(axis=1)
            view_df = view_df[mask]
        st.dataframe(view_df.tail(12).iloc[::-1], width="stretch", hide_index=True)

        exp1, exp2 = st.columns(2)
        with exp1:
            st.download_button("⬇ Export findings CSV", all_df.to_csv(index=False), "cybershield_all_findings.csv", "text/csv", width="stretch")
        with exp2:
            report = {
                "product": "CyberShield AI MVP",
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "scope": "Findings recorded in the current Streamlit session",
                "notice": "Rule-based prototype; validate findings before acting.",
                "summary": {"total": len(findings), "high": high, "medium": medium, "low": low, "info": info},
                "findings": findings
            }
            st.download_button("⬇ Export incident JSON", json.dumps(report, indent=2), "cybershield_incident_report.json", "application/json", width="stretch")
        if st.button("Clear session findings", type="secondary"):
            st.session_state.findings = []
            st.rerun()
    else:
        st.info("No findings yet. Run a file, URL, prompt, or log analysis to populate this table.")
        st.caption("Tip: use synthetic or authorized data for demos. Do not submit passwords, API keys, or confidential files.")

    st.divider()
    st.caption(
        "Scope & limitations: current findings are generated by the implemented checks and stored in the active app session. "
        "Rule-based checks can produce false positives or miss unknown threats. This dashboard does not imply continuous monitoring."
    )

elif page == "VisionGuard":
    st.subheader("🔎 VisionGuard — File Integrity Monitor")
    st.write(
        "Create a trusted file baseline, download it, and later compare "
        "files against it to detect content changes."
    )

    files = st.file_uploader(
        "Choose files to inspect",
        accept_multiple_files=True,
        key="vision_files"
    )

    if st.button("Scan selected files", key="scan_files"):
        if not files:
            st.warning("Choose at least one file.")
        else:
            rows = []
            for file in files:
                data = file.getvalue()
                rows.append({
                    "filename": file.name,
                    "size_bytes": len(data),
                    "sha256": sha256(data)
                })

            hashes = Counter(row["sha256"] for row in rows)
            for row in rows:
                row["duplicate_in_upload"] = hashes[row["sha256"]] > 1

                if row["duplicate_in_upload"]:
                    add_finding(
                        "VisionGuard", "Medium", "Duplicate file content",
                        f"{row['filename']} matches another uploaded file."
                    )

            st.session_state["vision_results"] = rows

    results = st.session_state.get("vision_results", [])

    if results:
        results_df = pd.DataFrame(results)
        st.dataframe(results_df, width="stretch")

        st.download_button(
            "Download trusted baseline (CSV)",
            results_df[["filename", "size_bytes", "sha256"]].to_csv(index=False),
            "visionguard_baseline.csv",
            "text/csv"
        )

        st.download_button(
            "Download scan results (CSV)",
            results_df.to_csv(index=False),
            "visionguard_scan_results.csv",
            "text/csv"
        )

    st.divider()
    st.markdown("### Verify against a trusted baseline")
    st.caption(
        "Upload a baseline CSV that you previously created and protected. "
        "A baseline created from an already compromised file cannot establish trust."
    )

    baseline_file = st.file_uploader(
        "Upload baseline CSV",
        type=["csv"],
        key="vision_baseline"
    )
    verify_files = st.file_uploader(
        "Select files to verify",
        accept_multiple_files=True,
        key="vision_verify_files"
    )

    if st.button("Verify integrity", key="verify_integrity"):
        if not baseline_file or not verify_files:
            st.warning("Upload both a baseline CSV and files to verify.")
        else:
            try:
                baseline_df = pd.read_csv(baseline_file)

                required = {"filename", "sha256"}
                if not required.issubset(baseline_df.columns):
                    st.error(
                        "Baseline must contain filename and sha256 columns."
                    )
                elif baseline_df["filename"].duplicated().any():
                    st.error(
                        "Baseline contains duplicate filenames. "
                        "Create a baseline with unique filenames."
                    )
                else:
                    baseline = dict(zip(
                        baseline_df["filename"].astype(str),
                        baseline_df["sha256"].astype(str)
                    ))

                    verification_rows = []

                    for file in verify_files:
                        current_hash = sha256(file.getvalue())
                        name = file.name

                        if name not in baseline:
                            status = "NOT IN BASELINE"
                            severity = "Medium"
                            add_finding(
                                "VisionGuard", severity,
                                "File absent from baseline",
                                f"{name} was not listed in the trusted baseline."
                            )
                        elif current_hash != baseline[name]:
                            status = "HASH MISMATCH"
                            severity = "High"
                            add_finding(
                                "VisionGuard", severity,
                                "File integrity mismatch",
                                f"{name} does not match its baseline SHA-256."
                            )
                        else:
                            status = "MATCH"
                        
                        verification_rows.append({
                            "filename": name,
                            "current_sha256": current_hash,
                            "integrity_status": status
                        })

                    verification_df = pd.DataFrame(verification_rows)
                    st.dataframe(
                        verification_df, width="stretch"
                    )

                    st.download_button(
                        "Download verification report",
                        verification_df.to_csv(index=False),
                        "visionguard_verification.csv",
                        "text/csv"
                    )

            except Exception as exc:
                st.error(f"Could not verify files: {exc}")


elif page == "PhishProof":
    st.subheader("🔗 PhishProof — Evidence-Based URL Risk Analysis")
    st.caption("Checks URL structure, performs a bounded live HTTP(S) response inspection, and checks reputation providers when configured. Live inspection blocks local/private destinations and does not execute scripts or download files for execution.")

    with st.container(border=True):
        with st.form("phishproof_url_form", clear_on_submit=False):
            url = st.text_input(
                "URL to investigate",
                placeholder="https://example.com/login",
                help="Paste a complete URL, including http:// or https://. Leading/trailing whitespace is trimmed; embedded whitespace/control characters are rejected."
            )
            analyze = st.form_submit_button("🔍 Investigate URL", type="primary", width="stretch")

    if analyze:
        report = investigate_url(url, check_live=True)
        st.session_state["phishproof_latest"] = report
        if report["verdict"] != "Invalid input":
            sev = "High" if report["verdict"] == "High risk" else "Medium" if report["verdict"] in ("Suspicious", "Needs review") else "Info"
            details = json.dumps({k: report[k] for k in ("url", "url_valid", "host", "scheme", "path", "port", "explicit_port", "score", "verdict", "evidence", "sources", "unknowns")}, ensure_ascii=False)
            add_finding("PhishProof", sev, f"URL analysis: {report['verdict']}", details)

    report = st.session_state.get("phishproof_latest")
    if report:
        st.divider()
        st.markdown("### Investigation results")
        m1, m2, m3 = st.columns(3)
        m1.metric("Risk score", f"{report['score']}/100")
        m2.metric("Assessment", report["verdict"])
        m3.metric("Evidence level", report["confidence"])
        st.progress(min(100, int(report["score"])) / 100)
        st.write("**Destination host:**", report["host"] or "Not parsed")
        detail_cols = st.columns(3)
        detail_cols[0].write("**Scheme**")
        detail_cols[0].code(report.get("scheme", "—"))
        detail_cols[1].write("**Path**")
        detail_cols[1].code(report.get("path", "—"))
        detail_cols[2].write("**Port**")
        detail_cols[2].code(f"{report.get('port')} (default)" if report.get("explicit_port") is None and report.get("port") else str(report.get("port") or "—"))

        if report["verdict"] in ("High risk", "Suspicious"):
            st.error(report["recommendation"])
        elif report["verdict"] == "Needs review":
            st.warning(report["recommendation"])
        elif report["verdict"] == "Invalid input":
            st.error(report["recommendation"])
        else:
            st.info(report["recommendation"])

        live = report.get("website_check", {})
        st.markdown("### Live website inspection")
        if not live.get("performed"):
            st.info("Live inspection was not requested for this result. Click Investigate URL to run it.")
        else:
            st.write("**Connection status:**", live.get("status", "Not available"))
            if live.get("http_status") is not None:
                st.write("**HTTP status code:**", live["http_status"])
            if live.get("final_url"):
                st.write("**Final URL:**", live["final_url"])
            if live.get("content_type"):
                st.write("**Content type:**", live["content_type"])
            if live.get("page_title"):
                st.write("**Page title:**", live["page_title"])
            if live.get("redirects"):
                with st.expander(f"Redirect chain ({len(live['redirects'])})"):
                    for hop in live["redirects"]:
                        st.write(f"HTTP {hop['status']}: {hop['from']} → {hop['to']}")
            if live.get("security_headers"):
                st.markdown("#### Response security headers")
                st.dataframe(pd.DataFrame([{"Header": key, "Value": value} for key, value in live["security_headers"].items()]), hide_index=True, width="stretch")
            if live.get("findings"):
                st.markdown("#### Live inspection observations")
                for item in live["findings"]:
                    st.markdown(f"- {item}")
            if live.get("error"):
                st.warning(live["error"])
            st.caption("Live inspection is a limited HTTP response check. It does not execute JavaScript, download or run files, prove site ownership, or guarantee safety. Dynamic sites and bot protections may limit the findings.")

        left, right = st.columns(2)
        with left:
            st.markdown("#### Evidence observed")
            for item in report["evidence"]:
                st.markdown(f"- {item}")
        with right:
            st.markdown("#### Reputation sources")
            if report["sources"]:
                for item in report["sources"]:
                    st.markdown(f"- {item}")
            else:
                st.write("No reputation provider returned a confirmed result.")
            st.markdown("#### Checks not completed / limitations")
            for item in report["unknowns"]:
                st.markdown(f"- {item}")

        st.download_button(
            "⬇️ Download investigation report (JSON)",
            json.dumps(report, indent=2, ensure_ascii=False),
            "phishproof_url_investigation.json",
            "application/json",
            width="stretch",
        )

    with st.expander("How PhishProof evaluates a URL"):
        st.markdown("""
        - **Syntax checks:** scheme, hostname, user-info tricks, IP addresses, punycode, unusual ports and excessive subdomains.
        - **Content clues:** suspicious account-related paths, encoded strings, redirect parameters, URL shorteners and executable-looking file paths.
        - **Lookalike clues:** basic checks for well-known brand names appearing on unrelated domains.
        - **Live website inspection:** makes a bounded HTTP(S) request, checks response status, redirects, content type, page title, selected security headers, and limited HTML clues. Local/private destinations are blocked and redirects are validated.
        - **Reputation checks:** optional Google Safe Browsing and VirusTotal lookups when API keys are configured.

        These are triage signals, not proof. Live inspection is not a full malware sandbox, does not execute page scripts, and cannot guarantee a URL is safe. A low score does not certify a URL as safe, and the brand/domain checks are intentionally simple.
        """)
    st.caption("Risk score is an explainable triage score, not a probability. A low score does not certify a URL as safe. Reputation results depend on provider coverage and API availability.")


elif page == "PromptFence AI":
    st.subheader("🧠 PromptFence AI — Prompt Security Scanner")
    st.warning(
        "Use synthetic test data. This prototype scans text using rules; "
        "it does not call an AI model or guarantee that secrets are protected."
    )

    prompt = st.text_area(
        "Text to inspect",
        placeholder="Paste a test prompt here. Do not paste real passwords, tokens, or confidential data.",
        height=180
    )

    if st.button("Scan text", key="promptfence_scan"):
        if not prompt.strip():
            st.warning("Enter some text to scan.")
        else:
            findings = scan_prompt(prompt)

            if findings:
                high_count = sum(f["severity"] == "High" for f in findings)
                medium_count = sum(f["severity"] == "Medium" for f in findings)

                a, b, c = st.columns(3)
                a.metric("Patterns detected", len(findings))
                b.metric("High severity", high_count)
                c.metric("Medium severity", medium_count)

                st.markdown("### Detection evidence")

                for finding in findings:
                    with st.expander(
                        f"{finding['severity']} — {finding['category']}",
                        expanded=True
                    ):
                        st.write(finding["explanation"])
                        st.write("**Recommended action:** " + finding["recommendation"])

                    add_finding(
                        "PromptFence AI",
                        finding["severity"],
                        finding["category"],
                        finding["explanation"] + " Recommendation: " +
                        finding["recommendation"]
                    )

                st.session_state["promptfence_results"] = findings
            else:
                st.success("No configured patterns were detected.")
                st.caption(
                    "This does not prove the text is safe. Unrecognized attacks "
                    "and sensitive-data formats may not be detected."
                )
                st.session_state["promptfence_results"] = []

    results = st.session_state.get("promptfence_results", [])
    if results:
        report = pd.DataFrame(results)
        st.download_button(
            "Download PromptFence report",
            report.to_csv(index=False),
            "promptfence_report.csv",
            "text/csv"
        )


elif page == "NetSage":
    st.subheader("📊 NetSage — Security Log Analyzer")
    st.caption("Rule-based detection prototype; validate alerts before acting.")

    threshold_mb = st.slider(
        "Large outbound transfer threshold (MB)",
        min_value=1,
        max_value=100,
        value=10
    )
    st.session_state["netsage_threshold_bytes"] = threshold_mb * 1_000_000

    uploaded = st.file_uploader(
        "Upload a security log CSV",
        type=["csv"],
        key="netsage_upload"
    )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Load sample logs", key="netsage_sample"):
            st.session_state["net_logs"] = make_sample_logs()
            st.session_state.pop("net_alerts", None)

    with col2:
        if st.button("Clear NetSage results", key="netsage_clear"):
            st.session_state.pop("net_logs", None)
            st.session_state.pop("net_alerts", None)
            st.rerun()

    if uploaded is not None:
        try:
            st.session_state["net_logs"] = pd.read_csv(uploaded)
            st.session_state.pop("net_alerts", None)
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

    df = st.session_state.get("net_logs")

    if df is not None:
        st.markdown("### Uploaded log preview")
        st.write(f"Rows: {len(df)} | Columns: {len(df.columns)}")
        st.dataframe(df.head(200), width="stretch")

        if st.button("Analyze security logs", key="netsage_analyze"):
            original_analyzer = analyze_logs
            alerts = original_analyzer(df)

            # Apply the threshold chosen in the UI.
            threshold = st.session_state.get(
                "netsage_threshold_bytes", 10_000_000
            )
            if "bytes_out" in df.columns:
                sizes = pd.to_numeric(df["bytes_out"], errors="coerce")
                large_rows = df.index[sizes >= threshold]
                alerts = [
                    a for a in alerts
                    if a["rule"] != "Large outbound transfer"
                ]
                for idx in large_rows:
                    alerts.append({
                        "severity": "Medium",
                        "rule": "Large outbound transfer",
                        "source_ip": str(df.loc[idx, "source_ip"]),
                        "evidence": (
                            f"Row {idx + 1}: {sizes.loc[idx]:,.0f} bytes; "
                            f"threshold is {threshold:,} bytes."
                        ),
                        "recommendation": (
                            "Validate this transfer against normal usage "
                            "and approved data-transfer policies."
                        )
                    })

            st.session_state["net_alerts"] = alerts

            # Share alerts with the common SOC Copilot dashboard.
            for alert in alerts:
                if alert["severity"] != "Info":
                    add_finding(
                        "NetSage",
                        alert["severity"],
                        alert["rule"],
                        f"{alert['evidence']} Recommendation: "
                        f"{alert['recommendation']}"
                    )

        alerts = st.session_state.get("net_alerts", [])

        if alerts:
            st.markdown("### Detection results")
            alert_df = pd.DataFrame(alerts)

            a, b, c = st.columns(3)
            a.metric("Total alerts", len(alerts))
            b.metric(
                "High",
                sum(x["severity"] == "High" for x in alerts)
            )
            c.metric(
                "Medium",
                sum(x["severity"] == "Medium" for x in alerts)
            )

            st.dataframe(alert_df, width="stretch")

            st.download_button(
                "Download NetSage alerts CSV",
                alert_df.to_csv(index=False),
                "netsage_alerts.csv",
                "text/csv"
            )

elif page == "SOC Copilot":
    st.subheader("📝 SOC Copilot — Incident Summary")
    findings = st.session_state.findings
    if not findings:
        st.info("Run one or more modules first. Findings will appear here.")
    else:
        df = pd.DataFrame(findings)
        st.dataframe(df, width="stretch")

        high = sum(item["severity"] == "High" for item in findings)
        medium = sum(item["severity"] == "Medium" for item in findings)
        st.markdown("### Summary")
        st.write(f"- Total recorded findings: **{len(findings)}**")
        st.write(f"- High severity: **{high}**")
        st.write(f"- Medium severity: **{medium}**")
        st.write(
            "- Review high-severity findings first, validate them manually, "
            "and document the response."
        )

        report = {
            "product": "CyberShield AI MVP",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "notice": "Rule-based prototype; validate findings before acting.",
            "summary": {
                "total_findings": len(findings),
                "high": high,
                "medium": medium
            },
            "findings": findings
        }
        st.download_button(
            "Download incident report JSON",
            json.dumps(report, indent=2),
            "cybershield_incident_report.json",
            "application/json"
        )
        st.download_button(
            "Download findings CSV",
            df.to_csv(index=False),
            "cybershield_findings.csv",
            "text/csv"
        )

    if st.button("Clear all findings"):
        st.session_state.findings = []
        st.rerun()
