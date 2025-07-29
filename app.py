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
            st.write("This email and password will be used for **sending test emails**.")
            st.write("For **validation**, a generic internal address will be used for SMTP checks, but a valid domain in your sender email field can
