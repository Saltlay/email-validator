import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import whois # Ensure you have `pip install python-whois`

# New imports for enhanced validation
from email_validator import validate_email as validate_syntax_strict, EmailNotValidError
import tldextract # Ensure you have `pip install tldextract`

# --- Configs ---
DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
DEFAULT_ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
DEFAULT_FROM_EMAIL = "check@yourdomain.com"

# DNS MX and WHOIS caching
mx_cache = {}
whois_cache = {}

# --- Helper Function for Domain Extraction ---
def get_registrable_domain(email_or_domain_string):
    """
    Extracts the registrable domain (e.g., 'google.com' from 'mail.google.com').
    """
    try:
        if '@' in email_or_domain_string:
            # If it's an email, extract domain part first
            domain_part = email_or_domain_string.split('@')[1]
        else:
            # If it's already a domain string
            domain_part = email_or_domain_string

        extracted = tldextract.extract(domain_part)
        # Combine domain and suffix to get the registrable domain
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        elif extracted.domain: # For domains without a public suffix (e.g., local network names)
            return extracted.domain
        else:
            return None # Cannot extract a meaningful registrable domain
    except Exception:
        return None

# --- Validators (Updated) ---
def is_valid_syntax(email):
    """
    Uses email_validator to check syntax strictly according to RFCs.
    """
    try:
        # check_deliverability=False because we handle MX/SMTP separately
        validate_syntax_strict(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def is_disposable(registrable_domain, disposable_domains):
    return registrable_domain in disposable_domains

def is_role_based(email_prefix, role_based_prefixes):
    return email_prefix.lower() in role_based_prefixes

def has_mx_record(registrable_domain):
    if registrable_domain in mx_cache:
        return mx_cache[registrable_domain]
    try:
        answers = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_cache[registrable_domain] = len(answers) > 0
        return mx_cache[registrable_domain]
    except Exception:
        mx_cache[registrable_domain] = False
        return False

def verify_smtp(email, registrable_domain, from_email):
    try:
        mx_records = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_records_sorted = sorted(mx_records, key=lambda r: r.preference)
        mx = str(mx_records_sorted[0].exchange).rstrip('.')

        server = smtplib.SMTP(mx, timeout=5)
        server.helo(from_email.split('@')[1])
        server.mail(from_email)
        code, _ = server.rcpt(email)
        server.quit()
        return code in [250, 251]
    except Exception:
        return False

# --- Get Domain Info (Updated to use registrable_domain) ---
def get_domain_info(registrable_domain):
    if registrable_domain in whois_cache:
        return whois_cache[registrable_domain]
    
    company_name = "N/A" # Default if not found or private
    
    try:
        w = whois.whois(registrable_domain)
        if hasattr(w, 'organization') and w.organization:
            company_name = w.organization if isinstance(w.organization, str) else w.organization[0]
        elif hasattr(w, 'registrant_organization') and w.registrant_organization:
            company_name = w.registrant_organization if isinstance(w.registrant_organization, str) else w.registrant_organization[0]
        elif hasattr(w, 'name') and w.name:
            company_name = w.name if isinstance(w.name, str) else w.name[0]
        else:
            company_name = "Private/No Org Info"
            
    except Exception:
        company_name = "Lookup Failed" # More specific error
        
    whois_cache[registrable_domain] = company_name
    return company_name

# --- Main Checker (Modified significantly) ---
def validate_email(email, disposable_domains, role_based_prefixes, from_email):
    email = email.strip()
    
    # Initialize result dictionary
    result = {
        "Email": email,
        "Domain": "N/A", # Will be updated with registrable domain
        "Company/Org": "N/A (Pending)", # Initial status
        "Syntax Valid": False,
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "Verdict": "❌ Invalid"
    }

    # 1. Syntax Validation (using email_validator)
    if not is_valid_syntax(email):
        result["Verdict"] = "❌ Invalid Syntax"
        result["Company/Org"] = "N/A (Invalid Syntax)"
        return result
    result["Syntax Valid"] = True
    
    # Extract domain and prefix after syntax is confirmed
    local_part, full_domain_from_email = email.split('@')
    registrable_domain = get_registrable_domain(full_domain_from_email)
    result["Domain"] = registrable_domain if registrable_domain else full_domain_from_email

    # If registrable_domain couldn't be determined, it's problematic
    if not registrable_domain:
        result["Verdict"] = "❌ Invalid Domain Format"
        result["Company/Org"] = "N/A (Invalid Domain)"
        return result

    # 2. Check for Disposable and Role-based
    result["Disposable"] = is_disposable(registrable_domain, disposable_domains)
    result["Role-based"] = is_role_based(local_part, role_based_prefixes)

    # 3. WHOIS Company Lookup (using registrable_domain)
    result["Company/Org"] = get_domain_info(registrable_domain)

    # 4. MX Record Check (using registrable_domain)
    result["MX Record"] = has_mx_record(registrable_domain)

    # 5. SMTP Verification (only if MX record exists and not disposable by default)
    # The current logic will try SMTP even for role-based/disposable if MX exists
    # You might want to skip SMTP for disposable/role-based if they are "final" verdicts for you.
    if result["MX Record"] and not result["Disposable"]: # Can modify this condition
        result["SMTP Valid"] = verify_smtp(email, registrable_domain, from_email) # Pass registrable domain for server.helo

    # Final Verdict Logic (refined order)
    if result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        result["Verdict"] = "✅ Valid"
    else:
        # Catch-all for other failures (e.g., no MX record, SMTP verification failed)
        result["Verdict"] = "❌ Invalid" 

    return result

# --- Streamlit UI ---
st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Comprehensive Email Validator Tool")

st.markdown("""
Welcome to the **Email Validator Tool**! This application helps you verify email addresses based on several criteria, including:
* **Enhanced Syntax:** Strict RFC-compliant email format check (e.g., `user@domain.com`).
* **Accurate Domain Resolution:** Correctly identifies the registrable domain (e.g., `example.com` from `mail.example.com`).
* **MX Record:** Verifies if the domain has Mail Exchange records (necessary for receiving emails).
* **SMTP Check:** Attempts to confirm if the email inbox actually exists (the most reliable but also slowest check).
* **Disposable Email Detection:** Identifies emails from temporary/disposable email services.
* **Role-based Email Detection:** Flags generic emails like `admin@` or `support@`.
* **Company/Organization Lookup:** Attempts to retrieve organization name via public WHOIS data.
""")

st.divider()

# --- Top Section: Intro Text and Configuration in Columns ---
intro_text_col, config_col = st.columns([3, 1])

with intro_text_col:
    st.subheader("Get Started")
    st.write("Input one or more email addresses below. Separate them with commas or newlines. Click 'Validate Emails' to begin.")
    st.warning("⚠️ **Important Note on 'Company/Org' Lookup:** This feature relies on public WHOIS data, which can often be private, incomplete, or inaccurate. Results for this column are 'best effort' and not guaranteed.")

with config_col:
    with st.expander("⚙️ Configuration Settings", expanded=False):
        st.info("Adjust the parameters for email validation. Your changes will apply to all subsequent validation runs.")
        
        st.subheader("Disposable Domains")
        st.write("Emails from these domains will be flagged as 'Disposable'.")
        disposable_input = st.text_area(
            "Add or remove domains (comma or newline separated):",
            value=", ".join(DEFAULT_DISPOSABLE_DOMAINS),
            height=100,
            key="disposable_domains_input"
        )
        disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

        st.subheader("Role-based Prefixes")
        st.write("Emails starting with these prefixes (e.g., `admin@`) will be flagged as 'Role-based'.")
        role_based_input = st.text_area(
            "Add or remove prefixes (comma or newline separated):",
            value=", ".join(DEFAULT_ROLE_BASED_PREFIXES),
            height=100,
            key="role_based_prefixes_input"
        )
        role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())

        st.subheader("SMTP 'From' Email Address")
        st.write("This email address is used as the 'sender' for SMTP verification. Use a real domain you control for best results.")
        from_email_input = st.text_input(
            "Enter your 'From' email:",
            value=DEFAULT_FROM_EMAIL,
            key="from_email_input",
            help="Example: check@yourdomain.com"
        )
        from_email_valid = is_valid_syntax(from_email_input) # Use the new strict syntax check here too
        if not from_email_valid:
            st.error("🚨 Invalid 'From' email format. Please correct.")


st.divider()

# --- Main Email Validator Content ---
st.subheader("Paste Emails Here")

user_input = st.text_area(
    "Emails to Validate",
    placeholder="e.g., alice@example.com, bob@company.net\ncontact@marketing.org",
    height=250,
    key="email_input"
)

col_btn, col_spacer = st.columns([1, 4])

if col_btn.button("✅ Validate Emails", use_container_width=True, type="primary"):
    if not from_email_valid:
        st.error("🚨 Cannot proceed: The 'From' email address in Configuration is invalid. Please correct it.")
    else:
        raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]
        
        if not raw_emails:
            st.warning("☝️ Please enter at least one email address to validate.")
        else:
            unique_emails = list(set(raw_emails))
            if len(raw_emails) != len(unique_emails):
                st.info(f"✨ Detected and removed **{len(raw_emails) - len(unique_emails)}** duplicate email(s). Processing **{len(unique_emails)}** unique email(s).")
            emails_to_validate = unique_emails
            
            with st.status(f"Validating {len(emails_to_validate)} email(s)... This might take a moment.", expanded=True) as status_container:
                progress_bar = st.progress(0, text="Starting validation...")
                
                results = []
                total_emails = len(emails_to_validate)

                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, from_email_input) for email in emails_to_validate]
                    for i, future in enumerate(futures):
                        results.append(future.result())
                        progress_percent = (i + 1) / total_emails
                        progress_bar.progress(progress_percent, text=f"Processing email {i + 1} of {total_emails}...")
                
                status_container.update(label="Validation Complete!", state="complete", expanded=False)
            
            df = pd.DataFrame(results)
            
            st.success("🎉 Validation complete! Here are your results:")

            # --- Summary Statistics ---
            st.subheader("📊 Validation Summary")
            verdict_counts = Counter(df['Verdict'])
            
            summary_cols = st.columns(len(verdict_counts) if len(verdict_counts) > 0 else 1)
            col_idx = 0
            
            metric_icons = {
                "✅ Valid": "✨",
                "❌ Invalid": "🚫",
                "⚠️ Disposable": "🗑️",
                "ℹ️ Role-based": "👥",
                "❌ Invalid Syntax": "📝", # New verdict for clarity
                "❌ Invalid Domain Format": "🌐" # New verdict for clarity
            }

            for verdict in sorted(verdict_counts.keys()):
                count = verdict_counts[verdict]
                with summary_cols[col_idx % len(summary_cols)]:
                    st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                col_idx += 1

            st.divider()

            # --- Filtering Results ---
            st.subheader("Detailed Results & Export")
            
            all_verdicts = df['Verdict'].unique().tolist()
            filter_options = ["All"] + sorted(all_verdicts)
            
            selected_verdict = st.selectbox(
                "🔍 Filter results by verdict type:", 
                filter_options, 
                help="Select 'All' to view all validated emails, or choose a specific verdict to filter."
            )

            filtered_df = df
            if selected_verdict != "All":
                filtered_df = df[df['Verdict'] == selected_verdict]

            st.dataframe(filtered_df, use_container_width=True, height=400)

            st.download_button(
                "⬇️ Download Filtered Results as CSV",
                data=filtered_df.to_csv(index=False).encode('utf-8'),
                file_name="email_validation_results.csv",
                mime="text/csv",
                help="Click to download the currently displayed (filtered) validation results as a CSV file. Columns: Email, Domain, Company/Org, Syntax Valid, MX Record, Disposable, Role-based, SMTP Valid, Verdict."
            )

st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")
