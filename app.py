import streamlit as st
import re
import smtplib
import dns.resolver
import pandas as pd
from io import StringIO

# -------------------- Email Permutator Logic --------------------

NICKNAME_MAP = {
    "johnathan": "john", "michael": "mike", "william": "will", "stephen": "steve",
    "jennifer": "jen", "daniel": "dan", "richard": "rich", "jessica": "jess",
    "james": "jim", "robert": "rob", "christopher": "chris", "matthew": "matt",
    "anthony": "tony", "andrew": "andy", "patrick": "pat", "nicholas": "nick"
}

def get_nickname(name):
    return NICKNAME_MAP.get(name.lower(), "")

def generate_permutations(first, middle, last, domain):
    parts = [first, middle, last]
    base_names = set()

    if first: base_names.add(first)
    if last: base_names.add(last)
    if middle: base_names.add(middle)
    if get_nickname(first): base_names.add(get_nickname(first))

    combos = set()

    for f in base_names:
        for l in base_names:
            if f != l:
                combos.update([
                    f"{f}.{l}", f"{f}{l}", f"{f}_{l}", f"{f[0]}{l}", f"{f}{l[0]}",
                    f"{l}.{f}", f"{l}{f}", f"{l}_{f}", f"{l[0]}{f}", f"{f[0]}.{l}"
                ])
        combos.add(f)

    return [f"{c.lower()}@{domain}" for c in combos]

# -------------------- Email Validator Logic --------------------

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
FROM_EMAIL = "check@yourdomain.com"
mx_cache = {}

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
    result["Disposable"] = is_disposable(email)
    result["Role-based"] = is_role_based(email)
    domain = email.split('@')[1]
    result["MX Record"] = has_mx_record(domain)
    if result["MX Record"]:
        result["SMTP Valid"] = verify_smtp(email)
    if all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]) and not result["Disposable"]:
        result["Verdict"] = "✅ Valid"
    return result

# -------------------- Streamlit UI --------------------

st.set_page_config(page_title="Email Permutator & Validator", layout="wide")
st.title("📧 Email Permutator + Validator Tool")

tab1, tab2 = st.tabs(["🔧 Permutate + Validate", "📁 Validate Uploaded Emails"])

# ------------- Tab 1: Permutator + Validator ----------------
with tab1:
    st.subheader("🔄 Generate email permutations and validate them")

    col1, col2 = st.columns(2)

    with col1:
        full_name = st.text_input("Enter Full Name").strip()
    with col2:
        raw_domain = st.text_input("Enter Domain (e.g., example.com or https://example.com)").strip()

    if full_name and raw_domain:
        # Normalize name
        name_parts = full_name.lower().replace(".", " ").replace(",", " ").split()
        first, middle, last = "", "", ""
        if len(name_parts) >= 1: first = name_parts[0]
        if len(name_parts) == 2: last = name_parts[1]
        if len(name_parts) >= 3:
            middle = name_parts[1]
            last = name_parts[2]

        # Normalize domain
        domain = raw_domain.lower().replace("http://", "").replace("https://", "").replace("www.", "").strip().split('/')[0]

        permutations = generate_permutations(first, middle, last, domain)

        if st.button("🚀 Generate & Validate Emails"):
            results = [validate_email(e) for e in permutations]
            df_results = pd.DataFrame(results)
            st.success(f"✅ Generated and validated {len(results)} permutations")
            st.dataframe(df_results)

            csv = df_results.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download CSV", data=csv, file_name="permutated_valid_emails.csv", mime="text/csv")

# ------------- Tab 2: Bulk Email Validation ----------------
with tab2:
    st.subheader("📁 Bulk Email Validation via CSV")
    st.markdown("Upload a CSV file with a column named `Email`.")

    uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        if "Email" in df.columns:
            email_list = df["Email"].dropna().astype(str).tolist()
            if st.button("🚀 Validate Emails"):
                results = [validate_email(email) for email in email_list]
                df_results = pd.DataFrame(results)
                st.success(f"✅ Validated {len(results)} emails")
                st.dataframe(df_results)

                csv = df_results.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download CSV", data=csv, file_name="validated_emails.csv", mime="text/csv")
        else:
            st.error("CSV must contain a column named 'Email'")
