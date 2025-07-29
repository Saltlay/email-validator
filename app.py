import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor

# --- Configs ---
# Default values for configuration, now editable in UI
DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
DEFAULT_ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
DEFAULT_FROM_EMAIL = "check@yourdomain.com"  # Replace with a real domain you own

# DNS MX caching
mx_cache = {}

# --- Validators ---
def is_valid_syntax(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

def is_disposable(email, disposable_domains):
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

def is_role_based(email, role_based_prefixes):
    prefix = email.split('@')[0].lower()
    return prefix in role_based_prefixes

def has_mx_record(domain):
    if domain in mx_cache:
        return mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        mx_cache[domain] = len(answers) > 0
        return mx_cache[domain]
    except Exception:
        mx_cache[domain] = False
        return False

def verify_smtp(email, from_email):
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=3)
        mx = str(mx_records[0].exchange)

        server = smtplib.SMTP(mx, timeout=5)
        server.helo(from_email.split('@')[1]) # Use the domain from FROM_EMAIL
        server.mail(from_email)
        code, _ = server.rcpt(email)
        server.quit()
        return code in [250, 251]
    except Exception:
        return False

# --- Main Checker ---
def validate_email(email, disposable_domains, role_based_prefixes, from_email):
    email = email.strip()
    result = {
        "Email": email,
        "Syntax Valid": False,
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "Verdict": "❌ Invalid"
    }

    if not is_valid_syntax(email):
        return result
    result["Syntax Valid"] = True

    result["Disposable"] = is_disposable(email, disposable_domains)
    result["Role-based"] = is_role_based(email, role_based_prefixes)

    domain = email.split('@')[1]
    result["MX Record"] = has_mx_record(domain)

    if result["MX Record"]:
        result["SMTP Valid"] = verify_smtp(email, from_email)

    if all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]) and not result["Disposable"]:
        result["Verdict"] = "✅ Valid"
    elif result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    return result

# --- Streamlit UI ---
st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Advanced Email Validator Tool")

st.markdown("""
Welcome to the **Email Validator Tool**! This application helps you verify email addresses based on several criteria, including syntax, MX records, SMTP verification, and checking for disposable or role-based emails.
""")

st.write("---")

## Configuration Settings
with st.expander("⚙️ Configuration Settings"):
    st.info("Customize the lists of disposable domains, role-based prefixes, and the 'From' email address for SMTP checks.")
    
    col1_config, col2_config = st.columns(2)

    with col1_config:
        disposable_input = st.text_area(
            "Disposable Domains (comma or newline separated)",
            value=", ".join(DEFAULT_DISPOSABLE_DOMAINS),
            height=150
        )
        disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

    with col2_config:
        role_based_input = st.text_area(
            "Role-based Prefixes (comma or newline separated)",
            value=", ".join(DEFAULT_ROLE_BASED_PREFIXES),
            height=150
        )
        role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())

    from_email_input = st.text_input(
        "SMTP 'From' Email Address (e.g., check@yourdomain.com)",
        value=DEFAULT_FROM_EMAIL
    )
    if not is_valid_syntax(from_email_input):
        st.error("Please enter a valid 'From' email address for SMTP checks.")
        from_email_valid
