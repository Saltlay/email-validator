import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import whois # Ensure you have `pip install python-whois`

# --- Configs ---
# Default values for configuration, now editable in UI
DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
DEFAULT_ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
DEFAULT_FROM_EMAIL = "check@yourdomain.com" # Default, can be overridden by user input

# DNS MX caching
mx_cache = {}
whois_cache = {} # Cache for WHOIS results

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
        answers = dns.resolver.resolve(domain, 'MX', 'IN', lifetime=3)
        mx_cache[domain] = len(answers) > 0
        return mx_cache[domain]
    except Exception:
        mx_cache[domain] = False
        return False

def verify_smtp(email, from_email):
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX', 'IN', lifetime=3)
        mx_records_sorted = sorted(mx_records, key=lambda r: r.preference)
        mx = str(mx_records_sorted[0].exchange).rstrip('.') # Ensure MX record is canonical

        server = smtplib.SMTP(mx, timeout=5)
        server.helo(from_email.split('@')[1]) # Use the domain from FROM_EMAIL
        server.mail(from_email)
        code, _ = server.rcpt(email)
        server.quit()
        return code in [250, 251]
    except Exception:
        return False

# --- Get Domain Info (with more robust error handling and explicit N/A) ---
def get_domain_info(domain):
    if domain in whois_cache:
        return whois_cache[domain]
    
    company_name = "N/A" # Default if not found or private
    
    try:
        w = whois.whois(domain)
        # Prioritize 'organization', then 'registrant_organization', then 'name'
        # Handle cases where attributes might be lists
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
        
    whois_cache[domain] = company_name
    return company_name

# --- Main Checker (Modified) ---
def validate_email(email, disposable_domains, role_based_prefixes, from_email):
    email = email.strip()
    
    # Pre-check for syntax to handle very malformed emails gracefully
    if not is_valid_syntax(email):
        return {
            "Email": email,
            "Domain": "N/A",
            "Company/Org": "N/A (Invalid Syntax)",
            "Syntax Valid": False,
            "MX Record": False,
            "Disposable": False,
            "Role-based": False,
            "SMTP Valid": False,
            "Verdict": "❌ Invalid Syntax"
        }
        
    domain = email.split('@')[1] # Extract domain after syntax check

    # Initialize result dictionary with default values
    result = {
        "Email": email,
        "Domain": domain,
        "Company/Org": "Fetching...", # Indicate active lookup
        "Syntax Valid": True, # Already checked
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "Verdict": "❌ Invalid" # Default, will be refined
    }

    # Perform WHOIS lookup
    result["Company/Org"] = get_domain_info(domain)

    # Perform other checks
    result["Disposable"] = is_disposable(email, disposable_domains)
    result["Role-based"] = is_role_based(email, role_based_prefixes)
    result["MX Record"] = has_mx_record(domain)

    if result["MX Record"] and not result["Disposable"]:
        result["SMTP Valid"] = verify_smtp(email, from_email)
    
    # Final Verdict Logic (refined order for clarity)
    if not result["Syntax Valid"]: # This path is handled by the early exit now, but kept for robustness
        result["Verdict"] = "❌ Invalid Syntax"
    elif result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        result["Verdict"] = "✅ Valid"
    else:
        result["Verdict"] = "❌ Invalid" # Catch-all for other failures (e.g., no MX, SMTP failed)

    return result

# --- Streamlit UI ---
st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Comprehensive Email Validator Tool")

st.markdown("""
Welcome to the **Email Validator Tool**! This application helps you verify email addresses based on several criteria, including:
* **Syntax:** Checks if the email format is correct.
* **MX Record:** Verifies if the domain has Mail Exchange records (necessary for receiving emails).
* **SMTP Check:** Attempts to confirm if the email inbox actually exists (the most reliable but also slowest check).
* **Disposable Email Detection:** Identifies emails from temporary/disposable email services.
* **Role-based Email Detection:** Flags generic emails like `admin@` or `support@`.
* **Company/Organization Lookup:** Attempts to retrieve organization name via public WHOIS data.

Use the tabs below to validate emails or configure settings.
""")

st.divider() # Visual separation

# --- Tab based navigation ---
tab1, tab2 = st.tabs(["⚡ Validate Emails", "⚙️ Configuration"])

# --- Configuration Tab Content ---
with tab2:
    st.header("⚙️ Configuration Settings")
    st.info("Adjust the parameters for email validation. Your changes will apply to all subsequent validation runs.")
    st.markdown("---") # Visual separator

    st.subheader("Disposable Domains")
    st.write("Emails from these domains will be flagged as 'Disposable'.")
    disposable_input = st.text_area(
        "Add or remove domains (comma or newline separated):",
        value=", ".join(DEFAULT_DISPOSABLE_DOMAINS),
        height=150,
        key="disposable_domains_input"
    )
    disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

    st.markdown("---") # Visual separator

    st.subheader("Role-based Prefixes")
    st.write("Emails starting with these prefixes (e.g., `admin@`) will be flagged as 'Role-based'.")
    role_based_input = st.text_area(
        "Add or remove prefixes (comma or newline separated):",
        value=", ".join(DEFAULT_ROLE_BASED_PREFIXES),
        height=150,
        key="role_based_prefixes_input"
    )
    role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())

    st.markdown("---") # Visual separator

    st.subheader("SMTP 'From' Email Address")
    st.write("This email address is used as the 'sender' for SMTP verification. Use a real domain you control for best results.")
    from_email_input = st.text_input(
        "Enter your 'From' email:",
        value=DEFAULT_FROM_EMAIL,
        key="from_email_input",
        help="Example: check@yourdomain.com"
    )
    if not is_valid_syntax(from_email_input):
        st.error("🚨 Please enter a valid email address format (e.g., user@domain.com). This is crucial for accurate SMTP checks.")
        from_email_valid = False
    else:
        from_email_valid = True

# --- Email Validator Tab Content ---
with tab1:
    st.header("🚀 Start Validation")
    st.info("""
        Enter the email addresses you wish to validate.
        You can enter them separated by commas, newlines, or a mix of both.
        """)
    st.warning("⚠️ **Important Note on 'Company/Org' Lookup:** This feature relies on public WHOIS data, which can often be private, incomplete, or inaccurate. Results for this column are 'best effort' and not guaranteed.")

    user_input = st.text_area(
        "Paste your email addresses here:",
        placeholder="e.g., alice@example.com, bob@company.net\ncontact@marketing.org",
        height=250,
        key="email_input"
    )

    col_btn, col_spacer = st.columns([1, 4]) # Smaller column for button, larger for spacer
    
    if col_btn.button("✅ Validate Emails", use_container_width=True, type="primary"):
        if not from_email_valid:
            st.error("🚨 Cannot proceed: The 'From' email address is invalid. Please correct it in the **Configuration** tab.")
        else:
            raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]
            
            if not raw_emails:
                st.warning("☝️ Please enter at least one email address to validate.")
            else:
                # --- Deduplication ---
                unique_emails = list(set(raw_emails))
                if len(raw_emails) != len(unique_emails):
                    st.info(f"✨ Detected and removed **{len(raw_emails) - len(unique_emails)}** duplicate email(s). Processing **{len(unique_emails)}** unique email(s).")
                emails_to_validate = unique_emails
                
                with st.status(f"Validating {len(emails_to_validate)} email(s)... This might take a moment.", expanded=True) as status_container:
                    progress_bar = st.progress(0, text="Starting validation...")
                    
                    results = []
                    total_emails = len(emails_to_validate)

                    # Pass the dynamically updated configuration to the validation function
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
                
                # Define icons/colors for better visual metrics
                metric_icons = {
                    "✅ Valid": "✨",
                    "❌ Invalid": "🚫",
                    "⚠️ Disposable": "🗑️",
                    "ℹ️ Role-based": "👥",
                    "❌ Invalid Syntax": "📝"
                }

                for verdict in sorted(verdict_counts.keys()): # Sort for consistent order
                    count = verdict_counts[verdict]
                    with summary_cols[col_idx % len(summary_cols)]: # Cycle columns
                        st.metric(label=f"{metric_icons.get(verdict, '')} {verdict}", value=count)
                    col_idx += 1

                st.divider() # Visual separation

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

                st.dataframe(filtered_df, use_container_width=True, height=400) # Give more height to dataframe

                st.download_button(
                    "⬇️ Download Filtered Results as CSV",
                    data=filtered_df.to_csv(index=False).encode('utf-8'), # Export filtered data
                    file_name="email_validation_results.csv",
                    mime="text/csv",
                    help="Click to download the currently displayed (filtered) validation results as a CSV file. Columns: Email, Domain, Company/Org, Syntax Valid, MX Record, Disposable, Role-based, SMTP Valid, Verdict."
                )

st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")
