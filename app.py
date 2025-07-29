import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import whois
from email_validator import validate_email as validate_syntax_strict, EmailNotValidError
import tldextract
import yagmail # New import for email sending

# --- Configs ---
DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
DEFAULT_ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
DEFAULT_FROM_EMAIL = "check@yourdomain.com"
DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587

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
            domain_part = email_or_domain_string.split('@')[1]
        else:
            domain_part = email_or_domain_string

        extracted = tldextract.extract(domain_part)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        elif extracted.domain:
            return extracted.domain
        else:
            return None
    except Exception:
        return None

# --- Validators ---
def is_valid_syntax(email):
    try:
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

def get_domain_info(registrable_domain):
    if registrable_domain in whois_cache:
        return whois_cache[registrable_domain]
    
    company_name = "N/A"
    
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
        company_name = "Lookup Failed"
        
    whois_cache[registrable_domain] = company_name
    return company_name

# --- Scoring Function ---
def calculate_deliverability_score(result):
    score = 100

    if not result["Syntax Valid"]:
        score -= 100
    elif result["Verdict"] == "❌ Invalid Domain Format":
        score -= 95
    elif result["Disposable"]:
        score -= 90
    elif result["Role-based"]:
        score -= 30
    else:
        if not result["MX Record"]:
            score -= 70
        if not result["SMTP Valid"]:
            score -= 50
    
    return max(0, score)

# --- Main Checker (Modified) ---
def validate_email(email, disposable_domains, role_based_prefixes, from_email, enable_company_lookup):
    email = email.strip()
    
    result = {
        "Email": email,
        "Domain": "N/A",
        "Company/Org": "N/A (Pending)",
        "Syntax Valid": False,
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "Verdict": "❌ Invalid",
        "Score": 0
    }

    if not is_valid_syntax(email):
        result["Verdict"] = "❌ Invalid Syntax"
        result["Company/Org"] = "N/A (Invalid Syntax)"
        result["Score"] = calculate_deliverability_score(result)
        return result
    result["Syntax Valid"] = True
    
    local_part, full_domain_from_email = email.split('@')
    registrable_domain = get_registrable_domain(full_domain_from_email)
    result["Domain"] = registrable_domain if registrable_domain else full_domain_from_email

    if not registrable_domain:
        result["Verdict"] = "❌ Invalid Domain Format"
        result["Company/Org"] = "N/A (Invalid Domain)"
        result["Score"] = calculate_deliverability_score(result)
        return result

    # --- Conditional Company Lookup ---
    if enable_company_lookup:
        result["Company/Org"] = get_domain_info(registrable_domain)
    else:
        result["Company/Org"] = "Lookup Disabled" # Indicate it was skipped

    result["Disposable"] = is_disposable(registrable_domain, disposable_domains)
    result["Role-based"] = is_role_based(local_part, role_based_prefixes)
    result["MX Record"] = has_mx_record(registrable_domain)

    if result["MX Record"] and not result["Disposable"]:
        result["SMTP Valid"] = verify_smtp(email, registrable_domain, from_email)

    if result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        result["Verdict"] = "✅ Valid"
    else:
        result["Verdict"] = "❌ Invalid"

    result["Score"] = calculate_deliverability_score(result)
    return result

# --- Email Sending Function ---
def send_email_via_yagmail(sender_email, sender_password, recipient_email, subject, body, smtp_host, smtp_port):
    try:
        if not sender_email or not sender_password or not recipient_email or not subject or not body:
            return False, "All sender email, password, recipient, subject, and body fields are required."

        if "@gmail.com" in sender_email.lower() and "@" not in sender_password:
             st.warning("For Gmail, if you have 2FA enabled, you might need an **App Password** instead of your regular password. See Gmail security settings.")

        yag = yagmail.SMTP(
            user=sender_email,
            password=sender_password,
            host=smtp_host if smtp_host else None,
            port=smtp_port if smtp_port else None,
            # For debugging, uncomment below, but ensure security in production
            # smtp_debug=True
        )
        yag.send(
            to=recipient_email,
            subject=subject,
            contents=body
        )
        return True, "Email sent successfully!"
    # The change is here: Catching the broader Exception first to get more details
    except Exception as e: # Changed from yagmail.YagmailError
        # You can inspect 'e' to see if it's a specific YagmailError subclass
        # or a different type of error.
        error_message = str(e)
        if "SMTPAuthenticationError" in error_message:
            return False, f"Authentication failed. Check your sender email and password (or App Password for Gmail). Error: {error_message}"
        elif "SMTPConnectError" in error_message:
            return False, f"Could not connect to SMTP server. Check host/port or internet connection. Error: {error_message}"
        # Fallback for any other unexpected errors
        return False, f"Failed to send email: An unexpected error occurred: {error_message}"


# --- Streamlit UI ---
st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Comprehensive Email Validator & Sender Tool")

st.markdown("""
Welcome to the **Email Validator & Sender Tool**! This application is designed to help you ensure the quality and deliverability of your email lists.

**Key Features:**
* **Enhanced Email Validation:** Utilizes strict RFC-compliant syntax checks, accurate domain resolution (identifying the true registrable domain), MX record verification, and direct SMTP mailbox existence checks.
* **Deliverability Scoring:** Each validated email receives a numerical score (0-100) indicating its likely deliverability, helping you prioritize or segment your email lists.
* **Disposable & Role-Based Detection:** Automatically flags emails from temporary services or generic addresses like `admin@` or `info@`.
* **Optional Company/Organization Lookup:** Attempts to identify the company or organization associated with the email's domain using public WHOIS data. This feature can be toggled On/Off in settings as its reliability varies.
* **Test Email Sending:** A built-in utility to send test emails, allowing you to verify your SMTP settings and ensure your messages can be sent successfully from within the app.
* **Customizable Configurations:** Easily adjust disposable domains, role-based prefixes, and SMTP sender details to match your specific needs.
""")

st.divider()

# --- Top Section: Intro Text and Configuration in Columns ---
intro_text_col, config_col = st.columns([3, 1])

with intro_text_col:
    st.subheader("🚀 Get Started")
    st.markdown("""
    This tool offers two primary functionalities, accessible via the tabs below:
    
    1.  **⚡ Email Validator:**
        * Paste a list of email addresses (comma or newline separated).
        * The tool will process each email, performing a series of checks for syntax, domain validity, MX records, and SMTP deliverability.
        * You'll receive a detailed table of results, including a **Deliverability Score** (0-100), where higher scores indicate a greater likelihood of successful delivery.
        * Results can be filtered by verdict and downloaded as a CSV.
    
    2.  **✉️ Send Test Email:**
        * Use this tab to quickly send a test email from your configured sender account.
        * It's perfect for verifying your SMTP settings and ensuring your email sending capabilities are working as expected.
    
    **Important:** Please review and set up your **Configuration Settings** in the expander on the right. This includes your sender email and password, which are crucial for SMTP checks and sending test emails.
    """)

with config_col:
    with st.expander("⚙️ Configuration Settings", expanded=False):
        st.info("Adjust the parameters for email validation and sending. Your changes will apply to all subsequent actions.")
        
        st.subheader("SMTP Sender Details")
        st.write("This email and password will be used for both SMTP verification and sending test emails.")
        sender_email_input = st.text_input(
            "Your Sender Email (e.g., yourname@gmail.com):",
            value=DEFAULT_FROM_EMAIL,
            key="sender_email_input",
            help="This is the 'From' address for verification and sending."
        )
        sender_password_input = st.text_input(
            "Sender Email Password / App Password:",
            type="password",
            key="sender_password_input",
            help="For Gmail with 2FA, use an **App Password** (Google Account -> Security -> App Passwords)."
        )
        
        st.markdown("---")
        st.write("**Advanced SMTP Settings (for non-Gmail or custom servers)**")
        smtp_host_input = st.text_input(
            "SMTP Host (e.g., smtp.gmail.com):",
            value=DEFAULT_SMTP_HOST,
            key="smtp_host_input"
        )
        smtp_port_input = st.number_input(
            "SMTP Port (e.g., 587 for TLS, 465 for SSL):",
            value=DEFAULT_SMTP_PORT,
            key="smtp_port_input",
            step=1
        )

        from_email_valid = is_valid_syntax(sender_email_input)
        if not from_email_valid:
            st.error("🚨 Invalid Sender Email format. Please correct.")

        st.markdown("---")
        st.subheader("Validation Specific Settings")
        st.write("Customize lists for email classification and enable/disable optional lookups.")

        # --- New: Toggle for Company Lookup ---
        enable_company_lookup = st.checkbox(
            "Enable Company/Organization Lookup (WHOIS)",
            value=True, # Default to on
            help="Toggle this to enable/disable retrieving company information via WHOIS. Disable if you find results are consistently 'Private' or 'N/A' or if it significantly slows down validation."
        )
        if not enable_company_lookup:
            st.info("Company/Organization Lookup is currently disabled. The 'Company/Org' column will show 'Lookup Disabled'.")


        disposable_input = st.text_area(
            "Disposable Domains (comma or newline separated):",
            value=", ".join(DEFAULT_DISPOSABLE_DOMAINS),
            height=100,
            key="disposable_domains_input"
        )
        disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

        role_based_input = st.text_area(
            "Role-based Prefixes (comma or newline separated):",
            value=", ".join(DEFAULT_ROLE_BASED_PREFIXES),
            height=100,
            key="role_based_prefixes_input"
        )
        role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())


st.divider()

# --- Main Tabs for Validator and Sender ---
tab_validator, tab_sender = st.tabs(["⚡ Email Validator", "✉️ Send Test Email"])

# --- Email Validator Tab Content ---
with tab_validator:
    st.header("🚀 Validate Your Emails")
    st.info("""
        Enter the email addresses you wish to validate.
        You can enter them separated by commas, newlines, or a mix of both.
        """)

    user_input = st.text_area(
        "Emails to Validate",
        placeholder="e.g., alice@example.com, bob@company.net\ncontact@marketing.org",
        height=250,
        key="email_input"
    )

    col_btn, col_spacer = st.columns([1, 4])
    
    if col_btn.button("✅ Validate Emails", use_container_width=True, type="primary"):
        if not from_email_valid:
            st.error("🚨 Cannot proceed: Your Sender Email (in Configuration) is invalid. Please correct it.")
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
                        # Pass the new enable_company_lookup flag to validate_email
                        futures = [executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, sender_email_input, enable_company_lookup) for email in emails_to_validate]
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
                    "❌ Invalid Syntax": "📝",
                    "❌ Invalid Domain Format": "🌐"
                }

                for verdict in sorted(verdict_counts.keys()):
                    count = verdict_counts[verdict]
                    with summary_cols[col_idx % len(summary_cols)]:
                        st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                    col_idx += 1
                
                if not df.empty:
                    avg_score = df['Score'].mean()
                    st.metric("⭐ Average Deliverability Score", f"{avg_score:.2f}")

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

                csv = filtered_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "⬇️ Download Filtered Results as CSV",
                    data=csv,
                    file_name="email_validation_results.csv",
                    mime="text/csv",
                    help="Click to download the currently displayed (filtered) validation results as a CSV file. Includes Email, Domain, Company/Org, Validation Flags, Verdict, and Deliverability Score."
                )

# --- Send Test Email Tab Content ---
with tab_sender:
    st.header("✉️ Send a Test Email")
    st.info("""
        Use this feature to send a test email from your configured sender account.
        This helps confirm your SMTP settings and ensure your emails are being sent successfully.
        """)
    
    st.warning("""
        **Gmail Users with 2-Step Verification:** You **MUST** generate an **App Password** for your Google account and use that in the password field in `Configuration Settings`. Your regular Gmail password will likely not work.
        """)

    recipient_test_email = st.text_input("Recipient Email:", key="recipient_test_email", placeholder="test@example.com")
    test_subject = st.text_input("Subject:", key="test_subject", placeholder="Test Email from Streamlit App")
    test_body = st.text_area("Email Body:", key="test_body", height=150, placeholder="Hello, this is a test email sent from the Streamlit Email Tool!")

    if st.button("🚀 Send Test Email", type="primary"):
        if not sender_email_input or not sender_password_input:
            st.error("🚨 Sender Email and Password are required in the Configuration Settings to send emails.")
        elif not recipient_test_email or not test_subject or not test_body:
            st.warning("Please fill in all recipient, subject, and body fields to send a test email.")
        else:
            with st.spinner("Sending email..."):
                success, message = send_email_via_yagmail(
                    sender_email_input, 
                    sender_password_input, 
                    recipient_test_email, 
                    test_subject, 
                    test_body,
                    smtp_host_input,
                    smtp_port_input
                )
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")

st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")
