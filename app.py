import re
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import whois
from email_validator import validate_email as validate_syntax_strict, EmailNotValidError
import tldextract
import yagmail
import time

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

    if enable_company_lookup:
        result["Company/Org"] = get_domain_info(registrable_domain)
    else:
        result["Company/Org"] = "Lookup Disabled"

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

        if smtp_port == 465:
            yag = yagmail.SMTP(
                user=sender_email,
                password=sender_password,
                host=smtp_host,
                port=smtp_port,
                ssl=True
            )
        else:
            yag = yagmail.SMTP(
                user=sender_email,
                password=sender_password,
                host=smtp_host,
                port=smtp_port,
                starttls=True
            )

        yag.send(
            to=recipient_email,
            subject=subject,
            contents=body
        )
        return True, "Email sent successfully!"
    except Exception as e:
        error_message = str(e)
        if "SMTPAuthenticationError" in error_message or "Authentication failed" in error_message:
            return False, f"Authentication failed. Check your sender email and password (or App Password for Gmail). Error: {error_message}"
        elif "SMTPConnectError" in error_message or "Connection refused" in error_message:
            return False, f"Could not connect to SMTP server. Check host/port or internet connection. Error: {error_message}"
        elif "WRONG_VERSION_NUMBER" in error_message:
             return False, f"SSL/TLS Error: Port/Encryption mismatch. Ensure you're using the correct port (e.g., 465 for SSL or 587 for TLS/STARTTLS) for your SMTP server. Error: {error_message}"
        
        return False, f"Failed to send email: An unexpected error occurred: {error_message}"

# --- New Module: Email Permutator ---
def generate_email_permutations(first_name, last_name, domain, nickname=None):
    """
    Generates common email address permutations for a given name and domain.
    Includes options for nicknames.
    """
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    dom = domain.lower().strip()
    nick = nickname.lower().strip() if nickname else None

    # Remove non-alphanumeric characters that might cause issues in email prefixes
    first = re.sub(r'[^a-z0-9]', '', first)
    last = re.sub(r'[^a-z0-9]', '', last)
    if nick:
        nick = re.sub(r'[^a-z0-9]', '', nick)

    permutations = set()

    # Common patterns
    if first and last:
        permutations.add(f"{first}.{last}@{dom}")
        permutations.add(f"{first}{last}@{dom}")
        permutations.add(f"{first}_{last}@{dom}")
        permutations.add(f"{last}.{first}@{dom}")
        permutations.add(f"{last}{first}@{dom}")
        permutations.add(f"{last}_{first}@{dom}")

        # Initial + Last Name
        if len(first) > 0:
            permutations.add(f"{first[0]}.{last}@{dom}")
            permutations.add(f"{first[0]}{last}@{dom}")
            permutations.add(f"{first[0]}_{last}@{dom}")
        
        # First Name + Last Initial
        if len(last) > 0:
            permutations.add(f"{first}.{last[0]}@{dom}")
            permutations.add(f"{first}{last[0]}@{dom}")
            permutations.add(f"{first}_{last[0]}@{dom}")
        
        # Initial + Initial
        if len(first) > 0 and len(last) > 0:
            permutations.add(f"{first[0]}.{last[0]}@{dom}")
            permutations.add(f"{first[0]}{last[0]}@{dom}")
            permutations.add(f"{first[0]}_{last[0]}@{dom}")

    # First Name Only
    if first:
        permutations.add(f"{first}@{dom}")
    
    # Last Name Only
    if last:
        permutations.add(f"{last}@{dom}")

    # Nickname (if provided)
    if nick:
        permutations.add(f"{nick}@{dom}")
        if first and nick:
            permutations.add(f"{nick}.{last}@{dom}")
            permutations.add(f"{first}.{nick}@{dom}")
            permutations.add(f"{nick}{last}@{dom}")
            permutations.add(f"{first}{nick}@{dom}")
            permutations.add(f"{nick}_{last}@{dom}")
            permutations.add(f"{first}_{nick}@{dom}")
        if last and nick:
            permutations.add(f"{last}.{nick}@{dom}")
            permutations.add(f"{nick}.{first}@{dom}")

    # Remove any empty strings or invalid formats that might have slipped in
    # And ensure they adhere to basic email format (contain @ and a domain part)
    final_emails = set()
    for email in permutations:
        if email and '@' in email and '.' in email.split('@')[1]:
            final_emails.add(email)

    return sorted(list(final_emails))


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
* **Email Permutator:** Generate common email address combinations for a given name and domain, including nicknames, to help you guess potential contact emails.
* **Customizable Configurations:** Easily adjust disposable domains, role-based prefixes, and SMTP sender details to match your specific needs.
""")

st.divider()

# --- Top Section: Intro Text and Configuration in Columns ---
intro_text_col, config_col = st.columns([3, 1])

with intro_text_col:
    st.subheader("🚀 Get Started")
    st.markdown("""
    This tool offers three primary functionalities, accessible via the tabs below:
    
    1.  **⚡ Email Validator:**
        * Paste a list of email addresses (comma or newline separated).
        * The tool will process each email, performing a series of checks for syntax, domain validity, MX records, and SMTP deliverability.
        * You'll receive a detailed table of results, including a **Deliverability Score** (0-100), where higher scores indicate a greater likelihood of successful delivery.
        * Results can be filtered by verdict and downloaded as a CSV.
    
    2.  **✉️ Send Test Email:**
        * Use this tab to quickly send a test email from your configured sender account.
        * It's perfect for verifying your SMTP settings and ensuring your email sending capabilities are working as expected.

    3.  **🧩 Email Permutator:**
        * Enter a person's first name, last name, and a domain. Optionally, add a nickname.
        * The tool will generate a comprehensive list of common email address combinations for that individual within the specified domain. This is useful for guessing professional email addresses.
    
    **Important:** Please review and set up your **Configuration Settings** in the expander on the right. This includes your sender email and password, which are crucial for SMTP checks and sending test emails.
    """)

with config_col:
    with st.expander("⚙️ Configuration Settings", expanded=True):
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
        st.info("""
        Common SMTP Ports:
        * **587:** Recommended for STARTTLS (explicit TLS). Most common.
        * **465:** For SSL (implicit TLS).
        * **25:** Unencrypted (often blocked/discouraged).
        """)
        smtp_host_input = st.text_input(
            "SMTP Host (e.g., smtp.gmail.com):",
            value=DEFAULT_SMTP_HOST,
            key="smtp_host_input"
        )
        smtp_port_input = st.number_input(
            "SMTP Port (e.g., 587):",
            value=DEFAULT_SMTP_PORT,
            key="smtp_port_input",
            step=1,
            help="Choose 587 for STARTTLS, 465 for SSL."
        )

        from_email_valid = is_valid_syntax(sender_email_input)
        if not from_email_valid:
            st.error("🚨 Invalid Sender Email format. Please correct.")

        st.markdown("---")
        st.subheader("Validation Specific Settings")
        st.write("Customize lists for email classification and enable/disable optional lookups.")

        enable_company_lookup = st.checkbox(
            "Enable Company/Organization Lookup (WHOIS)",
            value=True,
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

# --- Initialize session state for stop button ---
if 'stop_validation' not in st.session_state:
    st.session_state.stop_validation = False
if 'is_validating' not in st.session_state:
    st.session_state.is_validating = False

# --- Callback for Stop Button ---
def stop_validation_callback():
    st.session_state.stop_validation = True

# --- Main Tabs for Validator, Sender, and Permutator ---
tab_validator, tab_sender, tab_permutator = st.tabs(["⚡ Email Validator", "✉️ Send Test Email", "🧩 Email Permutator"])

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

    col_start_btn, col_stop_btn = st.columns([1, 1])
    
    if col_start_btn.button("✅ Validate Emails", use_container_width=True, type="primary", disabled=st.session_state.is_validating):
        st.session_state.stop_validation = False
        st.session_state.is_validating = True

        if not from_email_valid:
            st.error("🚨 Cannot proceed: Your Sender Email (in Configuration) is invalid. Please correct it.")
            st.session_state.is_validating = False
        else:
            raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]
            
            if not raw_emails:
                st.warning("☝️ Please enter at least one email address to validate.")
                st.session_state.is_validating = False
            else:
                unique_emails = list(set(raw_emails))
                if len(raw_emails) != len(unique_emails):
                    st.info(f"✨ Detected and removed **{len(raw_emails) - len(unique_emails)}** duplicate email(s). Processing **{len(unique_emails)}** unique email(s).")
                emails_to_validate = unique_emails
                
                with st.status(f"Validating {len(emails_to_validate)} email(s)... Please wait.", expanded=True) as status_container:
                    st.button("⏹️ Stop Validation", key="status_stop_btn", on_click=stop_validation_callback, help="Click to immediately halt the current validation process.")
                    
                    progress_bar = st.progress(0, text="Starting validation...")
                    
                    results = []
                    total_emails = len(emails_to_validate)

                    with ThreadPoolExecutor(max_workers=10) as executor:
                        futures = {executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, sender_email_input, enable_company_lookup): email for email in emails_to_validate}
                        
                        for i, future in enumerate(as_completed(futures)):
                            if st.session_state.stop_validation:
                                status_container.update(label="Validation Aborted by User!", state="error", expanded=True)
                                for f in futures:
                                    f.cancel()
                                break
                            
                            results.append(future.result())
                            progress_percent = (i + 1) / total_emails
                            progress_bar.progress(progress_percent, text=f"Processing email {i + 1} of {total_emails}...")
                    
                    if not st.session_state.stop_validation:
                        status_container.update(label="Validation Complete!", state="complete", expanded=False)
                    
                st.session_state.is_validating = False
                st.session_state.stop_validation = False 

                if results:
                    df = pd.DataFrame(results)
                    
                    if st.session_state.stop_validation:
                        st.warning("Validation was stopped. Displaying partial results:")
                    else:
                        st.success("🎉 Validation complete! Here are your results:")

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
                else:
                    st.info("No results to display. Validation might have been stopped prematurely or no valid emails were found.")

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

    can_send_email = from_email_valid and bool(sender_password_input) and bool(recipient_test_email) and bool(test_subject) and bool(test_body)

    if st.button("🚀 Send Test Email", type="primary", disabled=not can_send_email):
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

# --- Email Permutator Tab Content ---
with tab_permutator:
    st.header("🧩 Email Permutator")
    st.info("""
        Generate a list of common email address combinations for a person based on their name and domain.
        This tool is useful for guessing professional email addresses for outreach.
        """)
    st.warning("⚠️ **Important:** This tool generates *possible* email addresses, not *verified* ones. Always use the **Email Validator** tab to check the deliverability of generated emails before using them.")

    col_name1, col_name2 = st.columns(2)
    with col_name1:
        perm_first_name = st.text_input("First Name:", key="perm_first_name", placeholder="John")
    with col_name2:
        perm_last_name = st.text_input("Last Name:", key="perm_last_name", placeholder="Doe")
    
    perm_nickname = st.text_input("Nickname (Optional):", key="perm_nickname", placeholder="Johnny")
    perm_domain = st.text_input("Domain (e.g., example.com):", key="perm_domain", placeholder="company.com")

    if st.button("✨ Generate Emails", type="primary"):
        if not perm_first_name and not perm_last_name and not perm_nickname:
            st.warning("Please enter at least a First Name, Last Name, or Nickname to generate permutations.")
        elif not perm_domain:
            st.warning("Please enter a Domain to generate permutations.")
        else:
            with st.spinner("Generating permutations..."):
                generated_emails = generate_email_permutations(
                    first_name=perm_first_name,
                    last_name=perm_last_name,
                    domain=perm_domain,
                    nickname=perm_nickname if perm_nickname else None
                )
            
            if generated_emails:
                st.success(f"Generated {len(generated_emails)} possible email combinations:")
                
                # Display in a dataframe
                df_permutations = pd.DataFrame({"Possible Email": generated_emails})
                st.dataframe(df_permutations, use_container_width=True, height=300)

                # Display in a text area for easy copying
                st.subheader("Copy Generated Emails")
                st.text_area(
                    "Copy these emails:",
                    value="\n".join(generated_emails),
                    height=200,
                    key="generated_emails_text_area"
                )

                # Download button
                csv_permutations = df_permutations.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "⬇️ Download Generated Emails as CSV",
                    data=csv_permutations,
                    file_name="email_permutations.csv",
                    mime="text/csv",
                    help="Download the list of generated email permutations."
                )
                st.info("Remember to use the **Email Validator** tab to check the deliverability of these generated emails!")
            else:
                st.warning("No email combinations could be generated with the provided details. Please check your input.")

st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")
