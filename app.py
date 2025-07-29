import re
import smtplib
import dns.resolver
import csv
from concurrent.futures import ThreadPoolExecutor

# -- Configs --
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
FROM_EMAIL = "check@yourdomain.com"  # Replace with a real domain you own

# DNS MX caching
mx_cache = {}

# --- Validators ---
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

# --- Main Checker ---
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

# --- Run and Print ---
def run_bulk_checker(emails):
    print("🔍 Validating emails...\n")
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(validate_email, emails))

    # Print nicely
    print(f"{'Email':<40} | Syntax | MX | SMTP | Disposable | Role | Verdict")
    print("-" * 95)
    for r in results:
        print(f"{r['Email']:<40} |   {str(r['Syntax Valid'])[0]}   | {str(r['MX Record'])[0]} |  {str(r['SMTP Valid'])[0]}   |     {str(r['Disposable'])[0]}      |  {str(r['Role-based'])[0]}  | {r['Verdict']}")

    # Save to CSV
    with open("results.csv", mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print("\n✅ Done! Results saved to: results.csv")

# --- CLI Input ---
if __name__ == "__main__":
    print("📥 Enter email addresses (comma or newline separated):")
    raw_input = input("> ").strip()
    emails = [e.strip() for e in raw_input.replace(',', '\n').split('\n') if e.strip()]

    run_bulk_checker(emails)
