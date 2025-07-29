import streamlit as st
import re
import smtplib
import dns.resolver
import pandas as pd

# ------------------ Constants ------------------
DISPOSABLE_DOMAINS = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "trashmail.com", "tempmail.com", "yopmail.com"}
ROLE_BASED_PREFIXES = {"admin", "support", "info", "sales", "contact", "webmaster", "help"}
NICKNAME_MAP = {
    "johnathan": "john", "jonathan": "john", "michael": "mike", "william": "will", "robert": "rob",
    "richard": "rich", "joseph": "joe", "daniel": "dan", "stephen": "steve", "james": "jim",
    "alexander": "alex", "nicholas": "nick", "charles": "charlie", "andrew": "andy"
}
FROM_EMAIL = "check@yourdomain.com"
mx_cache = {}

# ------------------ Utility Functions ------------------
def clean_name(name):
    return re.sub(r'\s+', '', name.strip().lower())

def generate_nicknames(name):
    return [name] + ([NICKNAME_MAP[name]] if name in NICKNAME_MAP else [])

def generate_emails(first, middle, last, domain):
    firsts = generate_nicknames(first)
    middles = [middle] if middle else [""]
    lasts = [last] if last else [""]
    patterns = []

    for f in firsts:
        for m in middles:
            for l in lasts:
                combos = [
                    f, l, f + l, f + "." + l, f + "_" + l,
                    f[0] + l, f + l[0], f[0] + "." + l, f + m + l,
                    l + f, l + "." + f, f + m + "." + l
                ]
                patterns.extend(filter(None, combos))
    patterns = list(set(patterns))
    return [f"{p}@{domain}" for p in patterns if domain]

def is_valid_syntax(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

def is_disposable(email):
    domain = email.split('@')[1].lower()
    return domain in DISPOSABLE_DOMAINS

def is_role_based(email):
    prefix = email.split('@')[0].lower()
    return prefix in ROLE_BASED_PREFIXES

def has_mx_record(domain):
    if domain in mx_cache:
        return mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        mx_cache[domain] = len(answers) > 0
        return mx_cache[domain]
    except:
        mx_cache[domain] = False
        return False

def verify_smtp(email):
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=3)
        mx = str(mx_records[0].exchange)
        server = smtplib.SMTP(mx, timeout=5)
        server.helo("yourdomain.com")
        server.mail(FROM_EMAIL)
        code, _ = server.rcpt(email)
        server.quit()
        return code in [250, 251]
    except:
        return False

def validate_email(email):
    email = email.strip()
    result = {
        "Email": email,
        "Syntax": "❌",
        "MX": "❌",
        "Disposable": "✅" if is_disposable(email) else "❌",
        "Role-based": "✅" if is_role_based(email) else "❌",
        "SMTP": "❌",
        "Verdict": "❌ Invalid"
    }
    if not is_valid_syntax(email): return result
    result["Syntax"] = "✅"
    domain = email.split('@')[1]
    if has_mx_record(domain):
        result["MX"] = "✅"
        result["SMTP"] = "✅" if verify_smtp(email) else "❌"
    if result["Syntax"] == "✅" and result["MX"] == "✅" and result["SMTP"] == "✅" and result["Disposable"] == "❌":
        result["Verdict"] = "✅ Valid"
    return result

# ------------------ UI ------------------
st.set_page_config(page_title="Email Permutator & Validator", layout="wide")
st.title("📧 Email Permutator & Validator")
st.markdown("Enter name and domain to generate & validate emails.")

with st.form("input_form"):
    col1, col2 = st.columns(2)
    with col1:
        full_name = st.text_input("👤 Full Name (First Middle Last)", placeholder="e.g. John Michael Doe")
    with col2:
        domain = st.text_input("🌐 Domain or Website", placeholder="e.g. example.com or www.example.com")
    submit = st.form_submit_button("🚀 Generate & Validate")

if submit:
    name_parts = clean_name(full_name).split()
    first = name_parts[0] if len(name_parts) > 0 else ""
    middle = name_parts[1] if len(name_parts) == 3 else ""
    last = name_parts[-1] if len(name_parts) > 1 else ""

    domain = domain.lower().replace("https://", "").replace("http://", "").replace("www.", "").strip().split('/')[0]

    if not first or not domain:
        st.error("❗ Please enter both a valid name and domain.")
    else:
        with st.spinner("⏳ Generating and validating emails..."):
            emails = generate_emails(first, middle, last, domain)
            results = [validate_email(e) for e in emails]
            df = pd.DataFrame(results)
            st.success(f"✅ Done! {len(results)} permutations checked.")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download CSV", data=csv, file_name="email_results.csv", mime="text/csv")
