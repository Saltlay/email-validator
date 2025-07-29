import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import whois # New import for WHOIS lookup

# --- Configs ---
# Default values for configuration, now editable in UI
DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
DEFAULT_ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
FROM_EMAIL = "check@yourdomain.com" # Default, can be overridden by user input

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

# --- New Function: Get Domain Info ---
def get_domain_info(domain):
    if domain in whois_cache:
        return whois_cache[domain]
    
    company_name = "N/A"
    
    try:
        w = whois.whois(domain)
        # Prioritize 'organization', then 'registrant_organization', then 'name'
        if w and w.organization:
            company_name = w.organization
        elif w and w.registrant_organization:
            company_name = w.registrant_organization
        elif w and w.name: # This might be the individual's name if not a company
            company_name = w.name
        
    except Exception:
        # Handle cases where WHOIS lookup fails or domain is invalid/private
        company_name = "Private/Not Found"
        
    whois_cache[domain] = company_name
    return company_name

# --- Main Checker (Modified) ---
def validate_email(email, disposable_domains, role_based_prefixes, from_email):
    email = email.strip()
    domain = email.split('@')[1] # Extract domain early

    result = {
        "Email": email,
        "Domain": domain, # New field
        "Company/Org": "Looking up...", # New field, will be updated
        "Syntax Valid": False,
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "Verdict": "❌ Invalid"
    }

    if not is_valid_syntax(email):
        result["Company/Org"] = "N/A (Invalid Syntax)"
        return result
    result["Syntax Valid"] = True

    # Perform WHOIS lookup concurrently with other checks if possible, or before/after
    # For simplicity, we'll do it sequentially for each email in validate_email for now.
    # If performance is an issue for very large lists, consider a separate ThreadPool for WHOIS.
    result["Company/Org"] = get_domain_info(domain)

    result["Disposable"] = is_disposable(email, disposable_domains)
    result["Role-based"] = is_role_based(email, role_based_prefixes)

    result["MX Record"] = has_mx_record(domain)

    if result["MX Record"] and not result["Disposable"]: # Only attempt SMTP for non-disposable and with MX
        result["SMTP Valid"] = verify_smtp(email, from_email)
    
    # Final Verdict Logic
    if result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        result["Verdict"] = "✅ Valid"
    else:
        result["Verdict"] = "❌ Invalid"

    return result

# --- Streamlit UI ---
st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Advanced Email Validator Tool")

st.markdown("""
Welcome to the **Email Validator Tool**! This application helps you verify email addresses based on several criteria, including syntax, MX records, SMTP verification, and checking for disposable or role-based emails.
""")

st.write("---")

# --- Tab based navigation ---
tab1, tab2 = st.tabs(["✉️ Email Validator", "⚙️ Configuration"])

# --- Configuration Tab Content ---
with tab2:
    st.header("⚙️ Configuration Settings")
    st.info("Customize the lists of disposable domains, role-based prefixes, and the 'From' email address for SMTP checks. Changes here will apply to new validations.")
    
    col1_config, col2_config = st.columns(2)

    with col1_config:
        disposable_input = st.text_area(
            "Disposable Domains (comma or newline separated)",
            value=", ".join(DEFAULT_DISPOSABLE_DOMAINS),
            height=150,
            key="disposable_domains_input" # Added key for uniqueness
        )
        disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

    with col2_config:
        role_based_input = st.text_area(
            "Role-based Prefixes (comma or newline separated)",
            value=", ".join(DEFAULT_ROLE_BASED_PREFIXES),
            height=150,
            key="role_based_prefixes_input" # Added key for uniqueness
        )
        role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())

    from_email_input = st.text_input(
        "SMTP 'From' Email Address (e.g., check@yourdomain.com)",
        value=FROM_EMAIL, # Use the global FROM_EMAIL default
        key="from_email_input" # Added key for uniqueness
    )
    if not is_valid_syntax(from_email_input):
        st.error("Please enter a valid 'From' email address for SMTP checks.")
        from_email_valid = False
    else:
        from_email_valid = True

# --- Email Validator Tab Content ---
with tab1:
    st.header("✉️ Validate Your Emails")
    st.write("Input one or more email addresses below. Separate them with commas or newlines.")
    st.warning("Please note: Retrieving 'Company/Org' details relies on public WHOIS data, which can be limited, private, or not always accurate for all domains.")

    user_input = st.text_area(
        "Emails to Validate",
        placeholder="e.g., test@example.com, info@company.org\nuser@disposable.com",
        height=200,
        key="email_input" # Added key for uniqueness
    )

    # Layout for buttons and messages
    button_col, message_col = st.columns([1, 3])

    if button_col.button("🚀 Validate Emails", use_container_width=True):
        if not from_email_valid:
            message_col.error("Cannot proceed: The 'From' email address is invalid. Please correct it in the **Configuration** tab.")
        else:
            raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]
            
            if not raw_emails:
                message_col.warning("Please enter at least one email address to validate.")
            else:
                # --- Deduplication ---
                unique_emails = list(set(raw_emails))
                if len(raw_emails) != len(unique_emails):
                    st.info(f"Removed {len(raw_emails) - len(unique_emails)} duplicate email(s). Validating {len(unique_emails)} unique email(s).")
                emails_to_validate = unique_emails
                
                message_col.info(f"Processing {len(emails_to_validate)} unique email(s)... This may take some time due to WHOIS lookups.")
                progress_bar = st.progress(0)
                status_text = st.empty()

                results = []
                total_emails = len(emails_to_validate)

                # Pass the dynamically updated configuration to the validation function
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, from_email_input) for email in emails_to_validate]
                    for i, future in enumerate(futures):
                        results.append(future.result())
                        progress_bar.progress((i + 1) / total_emails)
                        status_text.text(f"Validated {i + 1} of {total_emails} emails. Getting company info...")
                
                progress_bar.empty() # Clear the progress bar after completion
                status_text.empty() # Clear the status text after completion

                df = pd.DataFrame(results)
                
                st.success("🎉 Validation complete! See results below:")

                # --- Summary Statistics ---
                st.subheader("📊 Validation Summary")
                verdict_counts = Counter(df['Verdict'])
                
                summary_cols = st.columns(len(verdict_counts) if len(verdict_counts) > 0 else 1)
                col_idx = 0
                for verdict, count in verdict_counts.items():
                    with summary_cols[col_idx]:
                        if verdict == "✅ Valid":
                            st.metric(label=verdict, value=count, delta_color="normal")
                        elif verdict == "❌ Invalid":
                            st.metric(label=verdict, value=count, delta_color="inverse")
                        else:
                            st.metric(label=verdict, value=count)
                    col_idx = (col_idx + 1) % len(summary_cols) # Cycle through columns if many verdicts

                # --- Filtering Results ---
                st.subheader("Detailed Results")
                
                # Get all unique verdicts for filtering options
                all_verdicts = df['Verdict'].unique().tolist()
                
                # Add "All" option to filter
                filter_options = ["All"] + sorted(all_verdicts) 
                selected_verdict = st.selectbox("Filter results by Verdict:", filter_options)

                filtered_df = df
                if selected_verdict != "All":
                    filtered_df = df[df['Verdict'] == selected_verdict]

                st.dataframe(filtered_df, use_container_width=True) # Make dataframe span full width

                csv = filtered_df.to_csv(index=False).encode('utf-8') # Export filtered data
                st.download_button(
                    "📥 Download Filtered Results as CSV",
                    data=csv,
                    file_name="email_validation_results.csv",
                    mime="text/csv",
                    help="Click to download the currently displayed (filtered) validation results as a CSV file."
                )

st.write("---")
st.markdown("Developed with ❤️ using Streamlit")
