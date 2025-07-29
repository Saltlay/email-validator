You're absolutely right\! My apologies again for that recurring `SyntaxError: unterminated string literal`. It seems a line break inside a string was missed during the last edit, causing the string to not be properly closed.

I've fixed that specific line on 448. Here's the complete, corrected code for your Streamlit application:

-----

```python
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
# Default lists for disposable domains and role-based prefixes
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
# Default sender email for SMTP checks. This should be a syntactically valid placeholder.
# It does NOT need to be a real, authenticated email for validation SMTP checks.
SMTP_CHECK_FROM_EMAIL = "noreply@emailvalidator.com" 

DEFAULT_FROM_EMAIL = "check@yourdomain.com" # This is for the UI field, actual authenticated sending
DEFAULT_SMTP_HOST = "smtp.gmail.com" 
DEFAULT_SMTP_PORT = 587 

# Caching for DNS MX records and WHOIS lookups to improve performance on repeat queries
mx_cache = {}
whois_cache = {}

# --- Helper Function for Domain Extraction ---
def get_registrable_domain(email_or_domain_string):
    """
    Extracts the registrable domain (e.g., 'google.com' from 'mail.google.com' or 'www.google.com').
    Uses tldextract for robust parsing according to Public Suffix List.
    """
    try:
        # If input is an email, extract the domain part first
        if '@' in email_or_domain_string:
            domain_part = email_or_domain_string.split('@')[1]
        else:
            domain_part = email_or_domain_string # Assume input is already a domain string

        # Use tldextract to get the registrable domain (e.g., 'google.com' from 'mail.google.com')
        extracted = tldextract.extract(domain_part)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        elif extracted.domain:
            # Handle cases like "localhost" or internal network names that don't have a public suffix
            return extracted.domain
        else:
            return None # Cannot extract a meaningful registrable domain
    except Exception:
        return None

# --- Validators ---
def is_valid_syntax(email):
    """
    Checks email syntax strictly according to RFCs using the email_validator library.
    """
    try:
        # We handle MX/SMTP separately, so check_deliverability=False here
        validate_syntax_strict(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def is_disposable(registrable_domain, disposable_domains):
    """
    Checks if a domain is in the list of known disposable email domains.
    """
    return registrable_domain in disposable_domains

def is_role_based(email_prefix, role_based_prefixes):
    """
    Checks if the local part (prefix) of an email indicates a role-based address.
    """
    return email_prefix.lower() in role_based_prefixes

def has_mx_record(registrable_domain):
    """
    Checks if a domain has Mail Exchange (MX) records, indicating it can receive email.
    Results are cached to prevent redundant DNS lookups.
    """
    if registrable_domain in mx_cache:
        return mx_cache[registrable_domain]
    try:
        # Resolve MX records for the domain
        answers = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_cache[registrable_domain] = len(answers) > 0 # True if at least one MX record found
        return mx_cache[registrable_domain]
    except Exception:
        mx_cache[registrable_domain] = False
        return False

# --- Core SMTP Verification Function (Corrected) ---
def verify_smtp(email, registrable_domain): # Removed 'from_email' as parameter, use internal constant
    """
    Attempts to verify the existence of an email mailbox via SMTP.
    This is the most reliable but also the slowest check.
    Uses a generic 'MAIL FROM' address.
    """
    try:
        # Resolve MX records to find the mail server
        mx_records = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_records_sorted = sorted(mx_records, key=lambda r: r.preference) # Prioritize by preference
        mx = str(mx_records_sorted[0].exchange).rstrip('.') # Get the primary MX server hostname

        # Connect to the SMTP server
        server = smtplib.SMTP(mx, timeout=5)
        
        # Use a generic, syntactically valid email for HELO and MAIL FROM
        # This email does NOT need to be real or authenticated.
        generic_from_domain = SMTP_CHECK_FROM_EMAIL.split('@')[1]
        server.helo(generic_from_domain) 
        server.mail(SMTP_CHECK_FROM_EMAIL) 
        
        code, _ = server.rcpt(email) # Ask if recipient exists (RCPT TO)
        server.quit() # Disconnect
        return code in [250, 251] # 250: Mail action okay, 251: User not local but will forward
    except Exception:
        return False

def get_domain_info(registrable_domain):
    """
    Attempts to retrieve company/organization information using WHOIS data for the given domain.
    Results are cached. Note: WHOIS data is often private or incomplete.
    """
    if registrable_domain in whois_cache:
        return whois_cache[registrable_domain]
    
    company_name = "N/A" # Default value if no info found or lookup fails
    
    try:
        w = whois.whois(registrable_domain)
        # Prioritize organization, then registrant_organization, then name (which might be an individual)
        if hasattr(w, 'organization') and w.organization:
            company_name = w.organization if isinstance(w.organization, str) else w.organization[0]
        elif hasattr(w, 'registrant_organization') and w.registrant_organization:
            company_name = w.registrant_organization if isinstance(w.registrant_organization, str) else w.registrant_organization[0]
        elif hasattr(w, 'name') and w.name:
            company_name = w.name if isinstance(w.name, str) else w.name[0]
        else:
            company_name = "Private/No Org Info" # Explicitly state if info is hidden
            
    except Exception:
        company_name = "Lookup Failed" # Indicate if the WHOIS query itself failed
        
    whois_cache[registrable_domain] = company_name
    return company_name

# --- Scoring Function ---
def calculate_deliverability_score(result):
    """
    Calculates a deliverability score (0-100) based on validation results.
    """
    score = 100 # Start with a perfect score

    # Penalties based on verification results
    if not result["Syntax Valid"]:
        score -= 100 # Severely penalize invalid syntax - unusable email
    elif result["Verdict"] == "❌ Invalid Domain Format":
        score -= 95 # High penalty for non-resolvable/invalid domain format
    elif result["Disposable"]:
        score -= 90 # High penalty for disposable emails (very low deliverability)
    elif result["Role-based"]:
        score -= 30 # Moderate penalty for role-based (deliverability depends on use case, but higher risk)
    else: # If syntax is valid and not disposable/role-based, assess core deliverability
        if not result["MX Record"]:
            score -= 70 # Significant penalty for no MX record (cannot receive mail)
        if not result["SMTP Valid"]:
            score -= 50 # Penalty for SMTP failure (mailbox likely doesn't exist or is highly protected)
    
    return max(0, score) # Ensure score doesn't go below 0

# --- Main Validation Logic (Corrected) ---
def validate_email(email, disposable_domains, role_based_prefixes, enable_company_lookup): # Removed 'from_email' arg
    """
    Performs a comprehensive validation of a single email address.
    SMTP verification uses a generic internal sender address.
    """
    email = email.strip()
    
    # Initialize result dictionary with default/pending values
    result = {
        "Email": email,
        "Domain": "N/A", # Will be updated with registrable domain
        "Company/Org": "N/A (Pending)", # Initial status for company lookup
        "Syntax Valid": False,
        "MX Record": False,
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False, # Will be set based on attempt
        "Verdict": "❌ Invalid", # Default verdict, will be refined
        "Score": 0 # Initial score
    }

    # 1. Syntax Validation (fastest check, early exit)
    if not is_valid_syntax(email):
        result["Verdict"] = "❌ Invalid Syntax"
        result["Company/Org"] = "N/A (Invalid Syntax)" # Company info not applicable for invalid syntax
        result["Score"] = calculate_deliverability_score(result)
        return result
    result["Syntax Valid"] = True
    
    # Extract domain and prefix after syntax is confirmed
    local_part, full_domain_from_email = email.split('@')
    registrable_domain = get_registrable_domain(full_domain_from_email)
    # Store the registrable domain, or the original domain if registrable couldn't be found
    result["Domain"] = registrable_domain if registrable_domain else full_domain_from_email

    # If a meaningful registrable domain couldn't be determined (e.g., 'user@.com')
    if not registrable_domain:
        result["Verdict"] = "❌ Invalid Domain Format"
        result["Company/Org"] = "N/A (Invalid Domain)"
        result["Score"] = calculate_deliverability_score(result)
        return result

    # 2. Conditional Company Lookup (based on user setting)
    if enable_company_lookup:
        result["Company/Org"] = get_domain_info(registrable_domain)
    else:
        result["Company/Org"] = "Lookup Disabled" # Explicitly state if skipped by user

    # 3. Check for Disposable and Role-based (fast checks)
    result["Disposable"] = is_disposable(registrable_domain, disposable_domains)
    result["Role-based"] = is_role_based(local_part, role_based_prefixes)

    # 4. MX Record Check
    result["MX Record"] = has_mx_record(registrable_domain)

    # 5. SMTP Verification (Restored logic: Attempt if MX exists and not disposable)
    # The verify_smtp function now uses the internal SMTP_CHECK_FROM_EMAIL.
    if result["MX Record"] and not result["Disposable"]:
        result["SMTP Valid"] = verify_smtp(email, registrable_domain) # No from_email arg
    else:
        # If no MX record or is disposable, SMTP check is logically not performed
        result["SMTP Valid"] = False

    # Final Verdict Logic (ordered by priority/impact)
    if result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        result["Verdict"] = "✅ Valid"
    else:
        # Catch-all for other failures (e.g., no MX record, SMTP verification failed)
        result["Verdict"] = "❌ Invalid"

    # Calculate final score
    result["Score"] = calculate_deliverability_score(result)
    return result

# --- Email Sending Function ---
def send_email_via_yagmail(sender_email, sender_password, recipient_email, subject, body, smtp_host, smtp_port):
    """
    Sends a test email using yagmail, handling common SMTP errors.
    """
    try:
        # Basic input validation
        if not sender_email or not sender_password or not recipient_email or not subject or not body:
            return False, "All sender email, password, recipient, subject, and body fields are required."

        # Specific warning for Gmail users about App Passwords
        if "@gmail.com" in sender_email.lower() and "@" not in sender_password:
             st.warning("For Gmail, if you have 2FA enabled, you might need an **App Password** instead of your regular password. See Google Account -> Security -> App Passwords.")

        # Initialize yagmail with explicit SSL/STARTTLS based on port
        if smtp_port == 465: # Implicit SSL/TLS
            yag = yagmail.SMTP(
                user=sender_email,
                password=sender_password,
                host=smtp_host,
                port=smtp_port,
                ssl=True
            )
        else: # For ports like 587 (STARTTLS) or 25
            yag = yagmail.SMTP(
                user=sender_email,
                password=sender_password,
                host=smtp_host,
                port=smtp_port,
                starttls=True # Explicitly attempt STARTTLS
            )

        # Send the email
        yag.send(
            to=recipient_email,
            subject=subject,
            contents=body
        )
        return True, "Email sent successfully!"
    except Exception as e: # Catch any exception during the sending process
        error_message = str(e)
        # Provide user-friendly error messages for common failures
        if "SMTPAuthenticationError" in error_message or "Authentication failed" in error_message or "authentication required" in error_message:
            return False, f"Authentication failed. Check your sender email and password (or App Password for Gmail). Error: {error_message}"
        elif "SMTPConnectError" in error_message or "Connection refused" in error_message or "No route to host" in error_message:
            return False, f"Could not connect to SMTP server. Check host/port or internet connection. Error: {error_message}"
        elif "WRONG_VERSION_NUMBER" in error_message or "SSLError" in error_message or "certificate verify failed" in error_message:
             return False, f"SSL/TLS Error: Port/Encryption mismatch. Ensure you're using the correct port (e.g., 465 for SSL or 587 for TLS/STARTTLS) for your SMTP server. Error: {error_message}"
        
        # Fallback for any other unexpected errors
        return False, f"Failed to send email: An unexpected error occurred: {error_message}"

# --- Email Permutator Logic ---
def generate_email_permutations_raw(first_name, last_name, domain, nickname=None):
    """
    Generates common email address permutations for a given name and domain, including nicknames.
    Returns a list of raw email strings, after basic cleaning and syntax check.
    """
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    dom = domain.lower().strip()
    nick = nickname.lower().strip() if nickname else None

    # Get initials safely
    first_initial = first[0] if first else ''
    last_initial = last[0] if last else ''
    nick_initial = nick[0] if nick else ''

    # Clean name parts: remove non-alphanumeric characters for email prefixes
    first_clean = re.sub(r'[^a-z0-9]', '', first)
    last_clean = re.sub(r'[^a-z0-9]', '', last)
    nick_clean = re.sub(r'[^a-z0-9]', '', nick) if nick else None
    
    permutations = set() # Use a set to automatically handle duplicates

    patterns_to_try = []

    # --- Common Email Patterns ---
    # Full Name Combinations
    if first_clean and last_clean:
        patterns_to_try.extend([
            f"{first_clean}.{last_clean}", f"{first_clean}{last_clean}", f"{first_clean}_{last_clean}",
            f"{last_clean}.{first_clean}", f"{last_clean}{first_clean}", f"{last_clean}_{first_clean}",
        ])
    
    # Initial + Last Name
    if first_initial and last_clean:
        patterns_to_try.extend([
            f"{first_initial}.{last_clean}", f"{first_initial}{last_clean}", f"{first_initial}_{last_clean}",
        ])

    # First Name + Last Initial
    if first_clean and last_initial:
        patterns_to_try.extend([
            f"{first_clean}.{last_initial}", f"{first_clean}{last_initial}", f"{first_clean}_{last_initial}",
        ])
    
    # Initial + Initial
    if first_initial and last_initial:
        patterns_to_try.extend([
            f"{first_initial}.{last_initial}", f"{first_initial}{last_initial}", f"{first_initial}_{last_initial}",
        ])

    # Single Name Only
    if first_clean:
        patterns_to_try.append(first_clean)
    if last_clean:
        patterns_to_try.append(last_clean)

    # Nickname Combinations
    if nick_clean:
        patterns_to_try.append(nick_clean)
        if first_clean and last_clean:
             patterns_to_try.extend([
                f"{nick_clean}.{last_clean}", f"{first_clean}.{nick_clean}",
                f"{nick_clean}{last_clean}", f"{first_clean}{nick_clean}",
                f"{nick_clean}_{last_clean}", f"{first_clean}_{nick_clean}",
            ])
        elif first_clean: # Nickname with only first name
            patterns_to_try.extend([
                f"{nick_clean}{first_clean}", f"{first_clean}{nick_clean}",
                f"{nick_clean}_{first_clean}", f"{first_clean}_{nick_clean}"
            ])
        elif last_clean: # Nickname with only last name
             patterns_to_try.extend([
                f"{nick_clean}{last_clean}", f"{last_clean}{nick_clean}",
                f"{nick_clean}_{last_clean}", f"{last_clean}_{nick_clean}"
            ])
    
    # Construct full emails and add to set if they pass basic syntax
    for p in patterns_to_try:
        if p: # Ensure the generated prefix pattern is not empty
            full_email = f"{p}@{dom}"
            if is_valid_syntax(full_email): # Use the robust syntax validator here
                permutations.add(full_email)

    return sorted(list(permutations)) # Return a sorted list of unique emails


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
* **Email Permutator with Validation:** Generate common email address combinations for a given name and domain (including nicknames), and then **automatically validate** these generated emails for deliverability.
* **Customizable Configurations:** Easily adjust disposable domains, role-based prefixes, and SMTP sender details to match your specific needs.
""")

st.divider() # Visual separator below the main intro

# --- Top Section: Intro Text and Configuration in Columns ---
intro_text_col, config_col = st.columns([3, 1])

with intro_text_col:
    st.subheader("🚀 Get Started")
    st.markdown("""
    This tool offers three primary functionalities, accessible via the tabs below:
    
    1.  **⚡ Email Validator:**
        * Paste a list of email addresses (comma or newline separated) for comprehensive validation.
        * Get detailed results including a **Deliverability Score** (0-100) and export options.
    
    2.  **✉️ Send Test Email:**
        * Quickly send a test email from your configured sender account to verify SMTP settings.

    3.  **🧩 Email Permutator:**
        * Generate a list of common email address combinations for a person (First Name, Last Name, Nickname, Domain).
        * **Automatically validates** all generated emails, providing scores and deliverability verdicts directly in the results table.
    
    **Important:** Please review and set up your **Configuration Settings** in the expander on the right. This includes your sender email and password, which are crucial for SMTP checks and sending test emails across the app.
    """)

with config_col:
    # Default to expanded for initial visibility, guiding users to setup
    with st.expander("⚙️ Configuration Settings", expanded=True):
        st.info("Adjust the parameters for email validation and sending. Your changes will apply to all subsequent actions.")
        st.divider() # Visual separation within expander

        with st.container(border=True): # Grouping SMTP details
            st.subheader("📬 SMTP Sender Details")
            # Corrected string literal for clarity
            st.write("For **sending test emails**, use your actual sender email and password. For **validation**, a generic internal address will be used for SMTP checks, but a valid domain in your sender email field can sometimes improve reliability of the SMTP check.")

            sender_email_input = st.text_input(
                "Your Sender Email (e.g., yourname@gmail.com):",
                value=DEFAULT_FROM_EMAIL,
                key="sender_email_input",
                help="This is the 'From' address for sending test emails. For validation, any syntactically valid email is sufficient for the SMTP check."
            )
            sender_password_input = st.text_input(
                "Sender Email Password / App Password:",
                type="password", # Mask the password input
                key="sender_password_input",
                help="Required only for **sending test emails**. For validation, no password is needed."
            )
            
            st.markdown("---") # Smaller divider within container
            st.write("**Advanced SMTP Settings (for non-Gmail or custom servers)**")
            st.info("""
            Common SMTP Ports:
            * **587:** Recommended for **STARTTLS** (explicit TLS). Most common.
            * **465:** For **SSL** (implicit TLS).
            * **25:** Unencrypted (often blocked/discouraged for sending).
            """)
            smtp_host_input = st.text_input(
                "SMTP Host (e.g., smtp.gmail.com):",
                value=DEFAULT_SMTP_HOST,
                key="smtp_host_input",
                help="The SMTP server address for your email provider."
            )
            smtp_port_input = st.number_input(
                "SMTP Port (e.g., 587):",
                value=DEFAULT_SMTP_PORT,
                key="smtp_port_input",
                step=1,
                help="The port number your SMTP server uses for sending email."
            )

            # Validate sender email format for sending test emails.
            # This doesn't block validation if invalid, but warns for sending functionality.
            from_email_valid_for_sending = is_valid_syntax(sender_email_input)
            if not from_email_valid_for_sending:
                st.error("🚨 Invalid Sender Email format. Please correct if you plan to send test emails.")
            if not sender_password_input:
                st.warning("⚠️ Sender Password is required for **sending test emails**.")

        st.divider() # Visual separation

        with st.container(border=True): # Grouping validation settings
            st.subheader("🔍 Validation Specific Settings")
            st.write("Customize lists for email classification and enable/disable optional lookups.")

            enable_company_lookup = st.checkbox(
                "Enable Company/Organization Lookup (WHOIS)",
                value=True, # Default to on
                help="Toggle this to enable/disable retrieving company information via WHOIS. Disable if you find results are consistently 'Private' or 'N/A' or if it significantly slows down validation."
            )
            if not enable_company_lookup:
                st.info("Company/Organization Lookup is currently disabled. The 'Company/Org' column will show 'Lookup Disabled'.")

            st.markdown("---") # Smaller divider within container
            disposable_input = st.text_area(
                "Disposable Domains (comma or newline separated):",
                value=", ".join(DISPOSABLE_DOMAINS),
                height=100,
                key="disposable_domains_input",
                help="Domains commonly used for temporary or disposable email addresses. Emails from these domains will be flagged."
            )
            disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

            st.markdown("---") # Smaller divider within container
            role_based_input = st.text_area(
                "Role-based Prefixes (comma or newline separated):",
                value=", ".join(ROLE_BASED_PREFIXES),
                height=100,
                key="role_based_prefixes_input",
                help="Email prefixes commonly used for roles (e.g., 'admin', 'support'). Emails with these prefixes will be flagged as role-based."
            )
            role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())


st.divider() # Visual separator before tabs

# --- Initialize session state for stop buttons and running flags ---
if 'stop_validation' not in st.session_state:
    st.session_state.stop_validation = False
if 'is_validating' not in st.session_state:
    st.session_state.is_validating = False
if 'stop_permutation_validation' not in st.session_state:
    st.session_state.stop_permutation_validation = False
if 'is_permutating_and_validating' not in st.session_state:
    st.session_state.is_permutating_and_validating = False


# --- Callbacks for Stop Buttons ---
def stop_validation_callback():
    st.session_state.stop_validation = True
def stop_permutation_validation_callback():
    st.session_state.stop_permutation_validation = True


# --- Main Tabs for Validator, Sender, and Permutator ---
tab_validator, tab_sender, tab_permutator = st.tabs(["⚡ Email Validator", "✉️ Send Test Email", "🧩 Email Permutator"])

# --- Email Validator Tab Content ---
with tab_validator:
    st.header("🚀 Validate Your Emails")
    st.markdown("""
    Paste a list of email addresses below. The tool will conduct a deep validation, checking syntax, domain existence, MX records, and performing SMTP mailbox verification.
    """)
    st.divider()

    user_input = st.text_area(
        "Enter emails here (separated by commas or newlines):",
        placeholder="e.g., alice@example.com, bob@company.net\ncontact@marketing.org",
        height=250,
        key="email_input"
    )

    # Use a container for consistent spacing around buttons
    with st.container():
        col_start_btn, col_spacer = st.columns([1, 4]) # col_stop_btn will be inside status

        # The Validate button's disabled state ensures it's not clickable while another process is running
        if col_start_btn.button("✅ Validate Emails", use_container_width=True, type="primary", disabled=st.session_state.is_validating or st.session_state.is_permutating_and_validating):
            st.session_state.stop_validation = False # Reset stop flag for new validation run
            st.session_state.is_validating = True # Set validating state
            
            raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]
            
            if not raw_emails:
                st.warning("☝️ Please enter at least one email address to validate.")
                st.session_state.is_validating = False # Reset state
            else:
                unique_emails = list(set(raw_emails))
                if len(raw_emails) != len(unique_emails):
                    st.info(f"✨ Detected and removed **{len(raw_emails) - len(unique_emails)}** duplicate email(s). Processing **{len(unique_emails)}** unique email(s).")
                emails_to_validate = unique_emails
                
                # --- Validation Status and Stop Button ---
                with st.status(f"Validating {len(emails_to_validate)} email(s)... Please wait.", expanded=True, state="running") as status_container:
                    # Place the Stop button directly inside the status container
                    st.button("⏹️ Stop Validation", key="status_stop_btn_validator", on_click=stop_validation_callback, help="Click to immediately halt the current validation process.")
                    
                    progress_bar = st.progress(0, text="Starting validation...")
                    
                    results = []
                    total_emails = len(emails_to_validate)

                    with ThreadPoolExecutor(max_workers=10) as executor:
                        # Corrected: No 'from_email' needed here anymore. It uses SMTP_CHECK_FROM_EMAIL internally.
                        futures = {executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, enable_company_lookup): email for email in emails_to_validate}
                        
                        for i, future in enumerate(as_completed(futures)):
                            # Check stop flag periodically
                            if st.session_state.stop_validation:
                                status_container.update(label="Validation Aborted by User! 🛑", state="error", expanded=True)
                                # Attempt to cancel any remaining futures that haven't started or are still pending
                                for f in futures:
                                    f.cancel()
                                break # Exit the loop
                            
                            results.append(future.result())
                            progress_percent = (i + 1) / total_emails
                            progress_bar.progress(progress_percent, text=f"Processing email {i + 1} of {total_emails}...")
                        
                        # Update status based on whether it was completed or stopped
                        if not st.session_state.stop_validation:
                            status_container.update(label="Validation Complete! 🎉", state="complete", expanded=False)
                        
                    # Reset state variables after validation attempt (either complete or aborted)
                    st.session_state.is_validating = False
                    st.session_state.stop_validation = False 

                    # Display results only if some results were collected
                    if results:
                        df = pd.DataFrame(results)
                        
                        if st.session_state.stop_validation:
                            st.warning("Validation was stopped. Displaying partial results:")
                        else:
                            st.success("🎉 Validation complete! Here are your results:")

                        st.subheader("📊 Validation Summary")
                        verdict_counts = Counter(df['Verdict'])
                        
                        # Dynamic columns for summary metrics (min 1, max 5 for layout)
                        summary_cols = st.columns(min(len(verdict_counts) + 1, 5))
                        col_idx = 0
                        
                        metric_icons = { # Emojis for visual flair
                            "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                            "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐"
                        }

                        for verdict in sorted(verdict_counts.keys()):
                            count = verdict_counts[verdict]
                            with summary_cols[col_idx % len(summary_cols)]:
                                st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                            col_idx += 1
                        
                        if not df.empty:
                            with summary_cols[col_idx % len(summary_cols)]: # Use next available summary column for average score
                                avg_score = df['Score'].mean()
                                st.metric("⭐ Avg. Score", f"{avg_score:.2f}")

                        st.divider() # Visual separation

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

                        st.dataframe(filtered_df, use_container_width=True, height=400) # Fixed height for consistency

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

st.write("") # Add some vertical space
# --- Send Test Email Tab Content ---
with tab_sender:
    st.header("✉️ Send a Test Email")
    st.markdown("""
    Use this feature to send a test email from your configured sender account. This helps confirm your SMTP settings and ensure your messages can be sent successfully.
    """)
    st.divider()
    
    st.warning("""
        **Gmail Users with 2-Step Verification:** You **MUST** generate an **App Password** for your Google account and use that in the password field in `Configuration Settings`. Your regular Gmail password will likely not work.
        """)

    recipient_test_email = st.text_input("Recipient Email:", key="recipient_test_email", placeholder="test@example.com", help="The email address to send the test email to.")
    test_subject = st.text_input("Subject:", key="test_subject", placeholder="Test Email from Streamlit App", help="The subject line of your test email.")
    test_body = st.text_area("Email Body:", key="test_body", height=150, placeholder="Hello, this is a test email sent from the Streamlit Email Tool!", help="The content of your test email.")

    # Disable send button if sender email/password are not provided/valid OR if validation is running
    can_send_email = (
        from_email_valid_for_sending and # Checks format of sender email
        bool(sender_password_input) and # Checks if password field is not empty
        bool(recipient_test_email) and 
        bool(test_subject) and 
        bool(test_body) and 
        not st.session_state.is_validating and # Check validator's running state
        not st.session_state.is_permutating_and_validating # Check permutator's running state
    )
    
    # Provide hints if button is disabled
    if not from_email_valid_for_sending or not sender_password_input:
        st.info("💡 Please set your 'Sender Email' and 'Password' in Configuration Settings to enable sending.")
    elif not (bool(recipient_test_email) and bool(test_subject) and bool(test_body)):
        st.info("💡 Fill in all fields (Recipient, Subject, Body) to enable sending the test email.")


    if st.button("🚀 Send Test Email", type="primary", disabled=not can_send_email):
        with st.spinner("Sending email..."):
            success, message = send_email_via_yagmail(
                sender_email_input, # Use the sender email from UI
                sender_password_input, # Use the sender password from UI
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

st.write("") # Add some vertical space
# --- Email Permutator Tab Content ---
with tab_permutator:
    st.header("🧩 Email Permutator & Validator")
    st.markdown("""
        Generate a list of common email address combinations for a person based on their name and domain.
        The tool will then **automatically validate** these generated emails against all deliverability checks.
        """)
    st.warning("⚠️ **Important:** While this tool generates possible emails, the validation process is crucial to determine their actual deliverability. Some valid permutations may not correspond to an active email address.")
    st.divider()

    col_name1, col_name2 = st.columns(2)
    with col_name1:
        perm_first_name = st.text_input("First Name:", key="perm_first_name", placeholder="John", help="The first name of the person.")
    with col_name2:
        perm_last_name = st.text_input("Last Name:", key="perm_last_name", placeholder="Doe", help="The last name of the person.")
    
    perm_nickname = st.text_input("Nickname (Optional):", key="perm_nickname", placeholder="Johnny", help="An optional nickname for more permutations.")
    perm_domain = st.text_input("Domain (e.g., example.com):", key="perm_domain", placeholder="company.com", help="The company or organization's domain name.")

    # Disable button if any required input fields are empty or if another process is running
    can_generate_and_validate = (
        (bool(perm_first_name) or bool(perm_last_name) or bool(perm_nickname)) and 
        bool(perm_domain) and 
        not st.session_state.is_permutating_and_validating and # Check its own running state
        not st.session_state.is_validating # Check if main validator is running
    )
    
    # Provide hints if button is disabled due to missing permutation inputs
    if not (bool(perm_first_name) or bool(perm_last_name) or bool(perm_nickname)):
        st.info("💡 Enter at least a First Name, Last Name, or Nickname to enable generation.")
    elif not perm_domain:
        st.info("💡 Enter a Domain (e.g., example.com) to enable generation.")
    
    # Hint that SMTP validation might be impacted if sender email is not valid
    if not from_email_valid_for_sending:
         st.warning("⚠️ **SMTP verification might be limited for generated emails!** Your Sender Email (in Configuration) is invalid. Full SMTP checks require a valid sender email for the MAIL FROM command.")


    col_gen_btn, col_stop_perm_btn_spacer = st.columns([1, 1]) # spacer for stop button placeholder

    if col_gen_btn.button("✨ Generate & Validate Emails", type="primary", disabled=not can_generate_and_validate):
        st.session_state.stop_permutation_validation = False
        st.session_state.is_permutating_and_validating = True

        if not perm_first_name and not perm_last_name and not perm_nickname:
            st.warning("Please enter at least a First Name, Last Name, or Nickname to generate permutations.")
            st.session_state.is_permutating_and_validating = False
        elif not perm_domain:
            st.warning("Please enter a Domain to generate permutations.")
            st.session_state.is_permutating_and_validating = False
        else:
            # --- Permutation Generation Status ---
            with st.status("Generating email permutations...", expanded=True, state="running") as gen_status:
                generated_emails_raw = generate_email_permutations_raw(
                    first_name=perm_first_name,
                    last_name=perm_last_name,
                    domain=perm_domain,
                    nickname=perm_nickname if perm_nickname else None
                )
                if generated_emails_raw:
                    gen_status.update(label=f"Generated {len(generated_emails_raw)} unique permutations. Now validating...", state="running", expanded=True)
                else:
                    gen_status.update(label="No permutations generated. Check input.", state="complete", expanded=False)
                    st.warning("No email combinations could be generated with the provided details. Please check your input.")
                    st.session_state.is_permutating_and_validating = False # Reset state
                    st.session_state.stop_permutation_validation = False # Reset stop flag
                    st.experimental_rerun() # Rerun to clear status and enable button

            # Only proceed to validation if permutations were generated and app is still running
            if generated_emails_raw and st.session_state.is_permutating_and_validating:
                # --- Permutation Validation Status ---
                with st.status(f"Validating {len(generated_emails_raw)} generated emails... Please wait.", expanded=True, state="running") as val_status_container:
                    # Stop button for permutation validation
                    st.button("⏹️ Stop Permutation Validation", key="status_stop_perm_btn", on_click=stop_permutation_validation_callback, help="Click to immediately halt the validation of generated emails.")
                    
                    progress_bar = st.progress(0, text="Starting validation of permutations...")
                    
                    validated_results = []
                    total_generated = len(generated_emails_raw)

                    with ThreadPoolExecutor(max_workers=10) as executor:
                        # Corrected: `validate_email` no longer takes `from_email` as a direct validation parameter.
                        # It uses the global `SMTP_CHECK_FROM_EMAIL`.
                        futures = {executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, enable_company_lookup): email for email in generated_emails_raw}
                        
                        for i, future in enumerate(as_completed(futures)):
                            # Check stop flag periodically
                            if st.session_state.stop_permutation_validation:
                                val_status_container.update(label="Permutation Validation Aborted by User! 🛑", state="error", expanded=True)
                                for f in futures:
                                    f.cancel()
                                break
                            
                            validated_results.append(future.result())
                            progress_percent = (i + 1) / total_generated
                            progress_bar.progress(progress_percent, text=f"Processing generated email {i + 1} of {total_generated}...")
                    
                    # Update status based on completion or abortion
                    if not st.session_state.stop_permutation_validation:
                        val_status_container.update(label="Permutation Validation Complete! 🎉", state="complete", expanded=False)
                    
                # Reset state variables after validation attempt (either complete or aborted)
                st.session_state.is_permutating_and_validating = False
                st.session_state.stop_permutation_validation = False

                # --- Display Validated Permutations ---
                if validated_results:
                    df_validated_permutations = pd.DataFrame(validated_results)
                    
                    if st.session_state.stop_permutation_validation:
                        st.warning("Permutation validation was stopped. Displaying partial results:")
                    else:
                        st.success("🎉 Permutations generated and validated! Here are the results:")

                    st.subheader("📊 Permutation Validation Summary")
                    perm_verdict_counts = Counter(df_validated_permutations['Verdict'])
                    
                    perm_summary_cols = st.columns(min(len(perm_verdict_counts) + 1, 5))
                    perm_col_idx = 0
                    
                    metric_icons = { # Reusing icons defined earlier
                        "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                        "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐"
                    }

                    for verdict in sorted(perm_verdict_counts.keys()):
                        count = perm_verdict_counts[verdict]
                        with perm_summary_cols[perm_col_idx % len(perm_summary_cols)]:
                            st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                        perm_col_idx += 1
                    
                    if not df_validated_permutations.empty:
                        with perm_summary_cols[perm_col_idx % len(perm_summary_cols)]:
                            avg_perm_score = df_validated_permutations['Score'].mean()
                            st.metric("⭐ Avg. Score", f"{avg_perm_score:.2f}")

                    st.divider()

                    st.subheader("Detailed Permutation Results & Export")
                    
                    perm_all_verdicts = df_validated_permutations['Verdict'].unique().tolist()
                    perm_filter_options = ["All"] + sorted(perm_all_verdicts)
                    
                    perm_selected_verdict = st.selectbox(
                        "🔍 Filter permutation results by verdict type:", 
                        perm_filter_options, 
                        key="perm_filter_select", # Unique key for this selectbox
                        help="Select 'All' to view all validated permutations, or choose a specific verdict to filter."
                    )

                    perm_filtered_df = df_validated_permutations
                    if perm_selected_verdict != "All":
                        perm_filtered_df = df[df['Verdict'] == perm_selected_verdict]

                    st.dataframe(perm_filtered_df, use_container_width=True, height=400)

                    csv_permutations_validated = perm_filtered_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        "⬇️ Download Validated Permutations as CSV",
                        data=csv_permutations_validated,
                        file_name="email_permutations_validated.csv",
                        mime="text/csv",
                        help="Download the list of generated and validated email permutations."
                    )
                else:
                    st.info("No validated permutations to display. Generation or validation might have been stopped prematurely, or no valid inputs were provided.")
            
        # This part handles the initial state where no generation/validation has run yet.
        # Ensure the disabled state is managed, as the button itself is conditional now.

st.write("") # Add some final vertical space
st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")
```
