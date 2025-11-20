# regex_censor.py
import re
import logging # Assuming logger is configured elsewhere

# It's good practice to define compiled regex patterns globally or at class level
# if they are used multiple times, to avoid recompilation.
# For this script structure, defining them within functions is fine,
# but for larger applications, consider pre-compiling.

def censor_text_regex(text, keywords, logger):
    """
    Censor sensitive information in text using regex patterns.
    Args:
        text (str): Text to censor.
        keywords (list): List of company keywords to help maintain context.
        logger (logging.Logger): Logger instance.
    Returns:
        str: Text with sensitive information censored.
    """
    if not text:
        logger.warning("Empty text provided for censoring")
        return "" # Return empty string for empty input for consistency
    
    logger.info("Beginning text censoring")
    original_length = len(text)
    
    # Track number of replacements for each type
    stats = {
        "company_names": 0,
        "emails": 0,
        "domains": 0,
        "api_keys": 0,
        "credit_cards": 0,
        "phones": 0,
        "ids": 0,
        "ips": 0,
        "addresses": 0,
        "dates": 0,
        "passwords": 0,
        "money": 0     # Added money category
    }
    
    censored_text = text
    
    # Order of operations is important.
    # More specific and less ambiguous patterns should generally run first.

    # 1. Censor company names (using keywords)
    logger.debug("Censoring company names")
    censored_text, count = censor_company_names(censored_text, keywords)
    stats["company_names"] = count
    
    # 2. Censor email addresses
    logger.debug("Censoring email addresses")
    censored_text, count = censor_emails(censored_text)
    stats["emails"] = count
    
    # 3. Censor domain names (ensure this doesn't over-censor parts of URLs already handled or emails)
    logger.debug("Censoring domain names")
    censored_text, count = censor_domains(censored_text)
    stats["domains"] = count
    
    # 4. Censor API keys and secrets (often specific formats)
    logger.debug("Censoring API keys and secrets")
    censored_text, count = censor_api_keys(censored_text)
    stats["api_keys"] = count
    
    # 5. Censor credit cards (specific formats, before generic numbers or phones)
    logger.debug("Censoring credit card numbers")
    censored_text, count = censor_credit_cards(censored_text)
    stats["credit_cards"] = count
    
    # 6. Censor monetary values (before phone numbers since both can contain digits)
    logger.debug("Censoring monetary values")
    censored_text, count = censor_money(censored_text)
    stats["money"] = count
    
    # 7. Censor phone numbers (after credit cards and money to avoid misidentification)
    logger.debug("Censoring phone numbers")
    censored_text, count = censor_phone_numbers(censored_text)
    stats["phones"] = count
    
    # 8. Censor ID numbers (various formats, can be ambiguous)
    logger.debug("Censoring ID numbers")
    censored_text, count = censor_ids(censored_text)
    stats["ids"] = count
    
    # 9. Censor IP addresses
    logger.debug("Censoring IP addresses")
    censored_text, count = censor_ips(censored_text)
    stats["ips"] = count
    
    # 10. Censor physical addresses
    logger.debug("Censoring physical addresses")
    censored_text, count = censor_addresses(censored_text)
    stats["addresses"] = count
    
    # 11. Censor dates
    logger.debug("Censoring dates")
    censored_text, count = censor_dates(censored_text, text) # Pass original text for context
    stats["dates"] = count
    
    # 12. Censor passwords and tokens (can be very generic, so context is key)
    # Run this after more specific identifiers like API keys.
    logger.debug("Censoring passwords and tokens")
    censored_text, count = censor_passwords(censored_text)
    stats["passwords"] = count
    
    # 13. Censor person names (often relies on context, run towards the end)
    # Running after passwords might prevent a name that is also a simple password
    # (used in a password context) from being censored as a name first.
    
    # Log statistics
    total_replacements = sum(stats.values())
    logger.info(f"Censoring complete: {total_replacements} replacements made")
    for key, value in stats.items():
        if value > 0:
            logger.info(f"  - {key}: {value} replacements")
    
    new_length = len(censored_text)
    logger.debug(f"Text length change: {original_length} -> {new_length} ({new_length - original_length} diff)")
    
    return censored_text

def censor_company_names(text, keywords):
    if not keywords:
        return text, 0
    count = 0
    # Using word boundaries and case-insensitivity
    # Escape keywords to ensure they are treated literally in regex
    patterns = [rf'\b{re.escape(kw)}\b' for kw in keywords]
    combined_pattern = re.compile('|'.join(patterns), re.IGNORECASE)
    
    def replace_company(match):
        nonlocal count
        # Prevent censoring already censored entities if they accidentally match a keyword
        if match.group(0).startswith("[") and match.group(0).endswith("]"):
            return match.group(0)
        count += 1
        return "[COMPANY_NAME]"
    
    censored_text = combined_pattern.sub(replace_company, text)
    return censored_text, count

def censor_emails(text):
    count = 0
    # Standard email pattern, fairly reliable
    email_pattern = re.compile(
        r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+@"  # Local part
        r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # Domain name parts
        r"[a-zA-Z]{2,6}"  # TLD
    )

    def replace_email(match):
        nonlocal count
        count += 1
        email = match.group(0)
        try:
            _, domain = email.split('@', 1)
            return f"[EMAIL:{domain}]"
        except ValueError:
            return "[EMAIL]" # Fallback
            
    censored_text = email_pattern.sub(replace_email, text)
    return censored_text, count

def censor_domains(text):
    count = 0
    # Pattern for domain names, including http(s) and www.
    # Negative lookbehind for '@' to avoid matching email domains if censor_emails failed.
    # Negative lookbehind for '[' to avoid matching already censored domain in email like [EMAIL:example.com]
    domain_pattern = re.compile(
        r'(?<![@\w\[])(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?!\w)'
    )
    
    def replace_domain(match):
        nonlocal count
        count += 1
        full_url = match.group(0)
        try:
            domain_part = full_url
            if '://' in domain_part:
                domain_part = domain_part.split('://', 1)[1]
            if domain_part.startswith('www.'):
                domain_part = domain_part[4:]
            
            # Avoid issues with splitting if domain_part is just "domain.com"
            parts = domain_part.split('.')
            if len(parts) > 1:
                tld = parts[-1]
                # Check if tld is not excessively long or contains invalid characters
                if re.match(r"^[a-zA-Z]{2,63}$", tld):
                     return f"[DOMAIN:.{tld}]"
            return "[DOMAIN]" # Fallback if TLD extraction is problematic
        except (ValueError, IndexError):
            return "[DOMAIN]"
            
    censored_text = domain_pattern.sub(replace_domain, text)
    return censored_text, count

def censor_api_keys(text):
    count = 0
    
    # More specific patterns first
    api_key_patterns = [
        # Common prefixes
        re.compile(r'(?i)\b(?:api_key|apikey|api-key|access_key|access-key|secret_key|secret-key|token)\s*[:=]\s*["\']?([a-zA-Z0-9_/+.-]{16,128})["\']?'), # Contextual keys
        re.compile(r'\bAKIA[0-9A-Z]{16}\b'),  # AWS Access Key ID
        re.compile(r'\b(A3T[A-Z0-9]|AMZN|ASCA|AGPA)[A-Z0-9]{8,}\b'), # Other AWS related
        re.compile(r'\bAIza[0-9A-Za-z\\-_]{35}\b'),  # Google API Key
        re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', re.IGNORECASE),  # UUID
        re.compile(r'\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b'),  # Stripe API Keys
        re.compile(r'\bgh[pousr]_[a-zA-Z0-9]{36,255}\b'),  # GitHub PATs
        re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,}\b'), # Slack tokens
        re.compile(r'\b(EAACEdEose0cBA[0-9A-Za-z]+)\b'), # Facebook
        re.compile(r'\b[A-Za-z0-9/+]{30,}={0,2}\b') # Generic Base64-like string, potentially a key (last resort, more prone to FPs)
    ]
    
    censored_text = text
    
    def replace_api_key(match):
        nonlocal count
        
        # Determine which group contains the key. group(1) if contextual, group(0) otherwise.
        key_value = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)
        full_match_text = match.group(0) # The whole string matched by the pattern

        # Avoid re-censoring placeholders
        if key_value.startswith("[") and key_value.endswith("]"):
            return full_match_text # Return the original match if it's already a placeholder

        count += 1
        
        # Type detection based on the matched key or context
        if 'AKIA' in key_value: return "[AWS_ACCESS_KEY]"
        if 'AIza' in key_value: return "[GOOGLE_API_KEY]"
        if key_value.startswith(('sk_', 'pk_')): return "[STRIPE_API_KEY]"
        if key_value.startswith('gh'): return "[GITHUB_TOKEN]"
        if key_value.startswith('xox'): return "[SLACK_TOKEN]"
        if 'EAACEdEose0cBA' in key_value: return "[FACEBOOK_TOKEN]"
        if '-' in key_value and len(key_value) > 20: return "[UUID_API_KEY]" # Likely UUID

        # Contextual replacement from the first pattern
        if match.lastindex and match.lastindex > 0:
            if "secret" in full_match_text.lower(): return "[API_SECRET]"
            if "token" in full_match_text.lower(): return "[API_TOKEN]"
            return "[API_KEY]" # Default for contextual match
            
        return "[GENERIC_API_KEY]" # Default for other direct matches

    for pattern in api_key_patterns:
        censored_text = pattern.sub(replace_api_key, censored_text)
        
    return censored_text, count

def censor_credit_cards(text):
    count = 0
    
    # Stricter patterns for credit card numbers. Using named groups for clarity.
    # Added negative lookahead for digits to ensure it's not part of a longer number.
    # Added negative lookahead for " [YEAR]" / " [DATE]" to avoid common FPs with IDs.
    # Added negative lookahead for placeholders.
    cc_patterns = [
        # Visa: 13 or 16 digits, starts with 4
        re.compile(r'(?<!\d)4\d{3}(?:[\s-]?\d{4}){2}[\s-]?\d{1,4}(?!\d)(?!\s*\[(?:YEAR|DATE|ID_NUMBER|PHONE))(?!\s*\[CC_EXPIRY])'),
        # Mastercard: 16 digits, starts with 51-55 or 2221-2720
        re.compile(r'(?<!\d)(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)(?:[\s-]?\d{4}){3}(?!\d)(?!\s*\[(?:YEAR|DATE|ID_NUMBER|PHONE))(?!\s*\[CC_EXPIRY])'),
        # American Express: 15 digits, starts with 34 or 37. Common formats: XXXX XXXXXX XXXXX or XXXX-XXXX-XXXX-XXX
        re.compile(r'(?<!\d)3[47]\d{2}(?:(?:[\s-]?\d{6}[\s-]?\d{5})|(?:(?:[\s-]?\d{4}){2}[\s-]?\d{3}))(?!\d)(?!\s*\[(?:YEAR|DATE|ID_NUMBER|PHONE))(?!\s*\[CC_EXPIRY])'),
        # Discover: 16 digits, various prefixes
        re.compile(r'(?<!\d)(?:6011|622(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5]))|64[4-9]\d|65\d{2})(?:[\s-]?\d{4}){3}(?!\d)(?!\s*\[(?:YEAR|DATE|ID_NUMBER|PHONE))(?!\s*\[CC_EXPIRY])'),
        # Generic pattern for numbers explicitly labeled as cards (more cautious with context)
        re.compile(r'(?i)(?:credit|debit|card|cc|visa|mastercard|amex|discover)\s*(?:number|num|#)?\s*[:=-]?\s*((?:\d[\s-]*){12,19}\d)(?!\d)(?!\s*\[(?:YEAR|DATE|ID_NUMBER|PHONE))(?!\s*\[CC_EXPIRY])')
    ]

    censored_text = text
    
    def replace_cc(match):
        nonlocal count
        
        # If matched by the contextual pattern, the card number is in group 1
        card_number_match = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)

        # Avoid re-censoring placeholders
        if card_number_match.startswith("[") and card_number_match.endswith("]"):
            return match.group(0) # Return the original full match

        count += 1
        
        digits = ''.join(c for c in card_number_match if c.isdigit())
        
        if digits.startswith('4') and (len(digits) == 13 or len(digits) == 16):
            return "[CREDIT_CARD:VISA]"
        elif (digits.startswith(('51','52','53','54','55')) or (222100 <= int(digits[:6]) <= 272099)) and len(digits) == 16:
            return "[CREDIT_CARD:MASTERCARD]"
        elif digits.startswith(('34', '37')) and len(digits) == 15:
            return "[CREDIT_CARD:AMEX]"
        elif (digits.startswith('6011') or digits.startswith('65') or \
              (622126 <= int(digits[:6]) <= 622925) or \
              (644000 <= int(digits[:6]) <= 649999)) and len(digits) == 16:
            return "[CREDIT_CARD:DISCOVER]"
        else:
            # If it was matched by a specific card pattern but doesn't fit type logic (e.g. due to spacing issues in original regex)
            # or by the generic contextual pattern, return a generic placeholder.
            return "[CREDIT_CARD]"

    for pattern in cc_patterns:
        censored_text = pattern.sub(replace_cc, censored_text)
        
    return censored_text, count

def censor_money(text):
    """
    Censor monetary values in dollars, shekels, and other currencies
    
    Args:
        text (str): Text to censor
        
    Returns:
        tuple: (censored_text, replacement_count)
    """
    count = 0
    
    # Patterns for monetary values
    money_patterns = [
        # Dollar amounts: $100, $1,000, $1,000.00, etc.
        re.compile(r'(?<!\w)\$\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)'),
        
        # Dollar amounts with text: 100 dollars, 1,000 USD, etc.
        re.compile(r'(?<!\w)[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:dollars|USD|US\$)(?!\w)', re.IGNORECASE),
        
        # Shekel amounts: ₪100, ₪1,000, ₪1,000.00, etc.
        re.compile(r'(?<!\w)₪\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)'),
        
        # Shekel amounts with text: 100 shekels, 1,000 ILS, 1,000 NIS, etc.
        re.compile(r'(?<!\w)[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:shekels?|ILS|NIS)(?!\w)', re.IGNORECASE),
        
        # Text referring to shekels: NIS 100, etc.
        re.compile(r'(?<!\w)(?:NIS|ILS)\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)', re.IGNORECASE),
        
        # Generic monetary expressions with common currency units
        re.compile(r'(?<!\w)(?:EUR|GBP|JPY|CHF|AUD|CAD|CNY)\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)', re.IGNORECASE),
        
        # Euro amounts: €100, etc.
        re.compile(r'(?<!\w)€\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)'),
        
        # Pound amounts: £100, etc.
        re.compile(r'(?<!\w)£\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?(?!\d)'),
        
        # Monetary amounts in context: "costs $100", "worth $500", etc.
        re.compile(r'(?i)(?:costs?|worth|value|amount|payment|fee|price|charge|rate|income|revenue|profit|loss|salary|wage|fine|total)\s+(?:is|of|:)?\s*(?:\$|₪|€|£)?\s*[0-9]{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s*(?:dollars|USD|shekels?|ILS|NIS|euros?|EUR|GBP|pounds?)?')
    ]
    
    censored_text = text
    
    # Replacement function
    def replace_money(match):
        nonlocal count
        
        # Avoid re-censoring placeholders
        money_value = match.group(0)
        if money_value.startswith("[") and money_value.endswith("]"):
            return money_value
            
        count += 1
        return "[MONEY]"
    
    # Apply each pattern
    for pattern in money_patterns:
        censored_text = pattern.sub(replace_money, censored_text)
    
    return censored_text, count

def censor_phone_numbers(text):
    count = 0
    # Patterns for various phone number formats.
    # Using word boundaries \b or lookarounds to avoid partial matches within longer numbers.
    # Prioritize more specific formats.
    phone_patterns = [
        # International format with country code: +1 555-123-4567 or +44 20 7946 0958
        re.compile(r'(?<!\d)(?:\+\d{1,4}[\s.-]?)?(?:\(?\d{1,4}\)?[\s.-]?)?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}(?!\d)'),
        # Israeli mobile: 05X-XXXXXXX or 05X-XXX-XXXX
        re.compile(r'(?<!\d)0(?:5\d|7[234678])(?:[\s.-]?\d{3}[\s.-]?\d{4}|[\s.-]?\d{7})(?!\d)'),
        # Israeli landline: 0X-XXXXXXX or 0X-XXX-XXXX (e.g., 02, 03, 04, 08, 09)
        re.compile(r'(?<!\d)0[23489](?:[\s.-]?\d{3}[\s.-]?\d{4}|[\s.-]?\d{7})(?!\d)'),
        # US format with area code: (555) 123-4567 or 555-123-4567
        re.compile(r'(?<!\d)(?:\(\d{3}\)[\s.-]?|\d{3}[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)'),
        # Contextual phone numbers
        re.compile(r'(?i)(?:phone|tel|cell|mobile|fax)\s*(?:number|num|#)?\s*[:=-]?\s*((?:\+\d{1,3}[\s.-]?)?(?:\(\d+\)[\s.-]?)?[\d\s.-]{7,17}\d)(?!\d)')
    ]

    censored_text = text
    
    def replace_phone(match):
        nonlocal count
        
        phone_number_match = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)

        if phone_number_match.startswith("[") and phone_number_match.endswith("]"):
            return match.group(0)

        count += 1
        
        # Basic context extraction (can be expanded)
        digits_only = "".join(filter(str.isdigit, phone_number_match))

        if phone_number_match.startswith('+'):
            plus_idx = phone_number_match.find('+')
            space_idx = phone_number_match.find(' ', plus_idx)
            dash_idx = phone_number_match.find('-', plus_idx)
            
            end_idx = -1
            if space_idx != -1 and dash_idx != -1:
                end_idx = min(space_idx, dash_idx)
            elif space_idx != -1:
                end_idx = space_idx
            elif dash_idx != -1:
                end_idx = dash_idx
            
            if end_idx != -1 and end_idx > plus_idx +1 : # Ensure there's a country code
                 country_code = phone_number_match[plus_idx:end_idx]
                 # Validate country code format (e.g. +1, +44, +972)
                 if re.match(r'^\+\d{1,4}$', country_code):
                    return f"[PHONE:{country_code}]"

        if digits_only.startswith('05') and (9 <= len(digits_only) <= 10): return "[PHONE:IL_MOBILE]"
        if digits_only.startswith('0') and (9 <= len(digits_only) <= 10): return "[PHONE:IL_LANDLINE]" # Simplified
        if len(digits_only) == 10 and not digits_only.startswith('0') and not digits_only.startswith('1'): return "[PHONE:US]" # Simplified US
        if len(digits_only) == 11 and digits_only.startswith('1'): return "[PHONE:US_LONG]" # Simplified US with 1

        return "[PHONE]" # Generic fallback
        
    for pattern in phone_patterns:
        censored_text = pattern.sub(replace_phone, censored_text)
        
    return censored_text, count

def censor_ids(text):
    count = 0
    # Patterns for various ID formats.
    # Using \b to ensure whole word matches where appropriate.
    id_patterns = [
        # Israeli ID (Teudat Zehut): 9 digits, sometimes with context
        re.compile(r'(?i)(?:\b(?:TZ|T\.Z\.|ID|id number|ת\.ז\.|תעודת זהות)\s*[:=-]?\s*)?(\b\d{9}\b)(?!\d)'),
        # Social Security Number (US): XXX-XX-XXXX or XXXXXXXXX
        re.compile(r'(?i)(?:\bSSN\s*[:=-]?\s*)?(\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b)(?!\d)'),
        # Passport numbers (generic, alphanumeric, common lengths)
        re.compile(r'(?i)\b(?:passport\s*(?:number|no)?\.?\s*[:=-]?\s*)([A-Z0-9]{6,15})\b'),
        re.compile(r'\b(?!AKIA)[A-Z]{1,2}\d{6,9}\b'), # Common passport structures like LDDDDDDD, LLDDDDDD
        # Employee ID - more contextual
        re.compile(r'(?i)\b(?:employee|emp|staff)\s*(?:id|number|#)\s*[:=-]?\s*([A-Za-z0-9\-_]{4,15})\b')
    ]
    
    censored_text = text
    
    def replace_id(match):
        nonlocal count
        id_value = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)
        if id_value.startswith("[") and id_value.endswith("]"):
            return match.group(0)
        count += 1
        
        # Add more specific type detection if needed based on matched pattern or context
        full_match_lower = match.group(0).lower()
        if "ssn" in full_match_lower or (len(id_value.replace("-","").replace(" ","")) == 9 and id_value.count('-')==2):
            return "[SSN_ID]"
        if "passport" in full_match_lower:
            return "[PASSPORT_ID]"
        if "tz" in full_match_lower or "ת.ז" in full_match_lower or (len(id_value) == 9 and id_value.isdigit()):
            return "[NATIONAL_ID:IL]"
        if "employee" in full_match_lower or "emp" in full_match_lower or "staff" in full_match_lower :
            return "[EMPLOYEE_ID]"
        return "[ID_NUMBER]"
        
    for pattern in id_patterns:
        censored_text = pattern.sub(replace_id, censored_text)
        
    return censored_text, count

def censor_ips(text):
    count = 0
    # IPv4: standard format
    ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    # IPv6: more comprehensive pattern
    ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b')

    original_text_for_ip_context = text # Use original text for context to avoid issues with partially censored IPs

    def replace_ipv4(match):
        nonlocal count
        ip = match.group(0)
        if ip.startswith("[") and ip.endswith("]"): return ip
        
        # Validate octets to reduce false positives (e.g. version numbers like 1.2.3.4)
        octets = list(map(int, ip.split('.')))
        if not all(0 <= o <= 255 for o in octets):
            return ip # Not a valid IPv4, don't censor

        count += 1
        # Basic private IP check
        if octets[0] == 10 or \
           (octets[0] == 172 and 16 <= octets[1] <= 31) or \
           (octets[0] == 192 and octets[1] == 168):
            return "[PRIVATE_IPV4]"
        return "[PUBLIC_IPV4]"

    def replace_ipv6(match):
        nonlocal count
        ip = match.group(0)
        if ip.startswith("[") and ip.endswith("]"): return ip
        count += 1
        return "[IPV6_ADDRESS]"
        
    censored_text = text # Start with the current state of censored text
    censored_text = ipv4_pattern.sub(replace_ipv4, censored_text)
    censored_text = ipv6_pattern.sub(replace_ipv6, censored_text)
    
    return censored_text, count

def censor_addresses(text):
    count = 0
    # Street types, trying to be broad for English
    street_types = r'(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Place|Pl|Square|Sq|Terrace|Ter|Way|Highway|Hwy|Parkway|Pkwy|Route|Rte|Trail|Trl)'
    # Common address keywords
    address_keywords = r'(?i)(?:address|location|office|hq|headquarters|residence|property)\s*[:=-]?\s*'
    
    address_patterns = [
        # Number + Street Name + Street Type: 123 Main St, 45 Bleecker Avenue
        re.compile(rf'\b\d+\s+(?:[A-Z][a-z]+\s+)*[A-Z][a-z]+\s+{street_types}\b', re.IGNORECASE),
        # Number + Street Name (without explicit type, more generic): 123 Evergreen Terrace
        re.compile(r'\b\d+\s+(?:[A-Z][a-z]+\s+){1,3}[A-Z][a-z]+\b', re.IGNORECASE),
        # P.O. Box: P.O. Box 123, PO Box 12345
        re.compile(r'\bP\.?O\.?\s*Box\s+\d+\b', re.IGNORECASE),
        # Contextual address: "address: 123 Main St, City, ST 12345"
        re.compile(rf'{address_keywords}(\d+\s+.*?{street_types}.*?\b\d{{5}}(?:-\d{{4}})?\b)', re.IGNORECASE),
        # Israeli addresses (simplified, רחוב/שדרות etc. followed by name and number)
        re.compile(r'\b(?:רחוב|רח\.?|שדרות|שד\.?|דרך|סמטה|כיכר)\s+[א-ת\s."\'-]+\s+\d+(?:[/\-]\d+)?[א-ת]?\b', re.IGNORECASE)
    ]
    
    censored_text = text
    
    def replace_address(match):
        nonlocal count
        addr_match = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)
        if addr_match.startswith("[") and addr_match.endswith("]"):
            return match.group(0)
        count += 1
        return "[ADDRESS]"
        
    for pattern in address_patterns:
        censored_text = pattern.sub(replace_address, censored_text)
        
    return censored_text, count

def censor_dates(text, original_doc_text): # Pass original_doc_text for context
    count = 0
    # More robust date patterns
    date_patterns = [
        # DD/MM/YYYY or MM/DD/YYYY, DD.MM.YYYY, etc.
        re.compile(r'\b(?<!\d)(?:0?[1-9]|[12]\d|3[01])([/.-])(?:0?[1-9]|1[0-2])\1(?:\d{4}|\d{2})\b(?!\d)'),
        # YYYY/MM/DD or YYYY-MM-DD (ISO like)
        re.compile(r'\b(?<!\d)\d{4}([/.-])(?:0?[1-9]|1[0-2])\1(?:0?[1-9]|[12]\d|3[01])\b(?!\d)'),
        # Month name formats: 25 Dec 2023, December 25, 2023, Dec. 25 2023
        re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(?:\d{4}|\d{2})\b', re.IGNORECASE),
        re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:\d{4}|\d{2})\b', re.IGNORECASE),
        # Year only if it's likely a significant year (e.g., in a date range or specific context)
        # This is risky, so keep it limited or use context. For now, avoid generic year pattern.
        # Contextual dates
        re.compile(r'(?i)(?:date\s*(?:of|of birth|issued|valid|expires|expiry|from|until|through)|dob)\s*[:=-]?\s*(\b(?:[0-9]+(?:st|nd|rd|th)?\s)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s\d+[\s,]*\d{2,4}\b|\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b|\b\d{4}[/.-]\d{1,2}[/.-]\d{1,2}\b)')
    ]
    
    censored_text = text
    
    dob_indicators = ['birth', 'born', 'dob', 'date of birth']
    expiry_indicators = ['expir', 'valid until', 'good through'] # 'valid' alone is too generic
    issue_indicators = ['issue', 'created on']

    def replace_date(match):
        nonlocal count
        
        date_str = match.group(1) if match.lastindex and match.lastindex > 0 else match.group(0)
        if date_str.startswith("[") and date_str.endswith("]"):
            return match.group(0)

        count += 1
        
        # Context checking (look around the match in the *original* text)
        # This helps determine if it's a DoB, Expiry, etc.
        # match.group(0) is the full string matched by the pattern, including context if captured by the pattern itself.
        # For patterns without context capture, we look around match.start() / match.end() in original_doc_text
        
        context_window = 30
        start_pos = max(0, match.start() - context_window)
        end_pos = min(len(original_doc_text), match.end() + context_window)
        surrounding_text = original_doc_text[start_pos:end_pos].lower()
        
        # Check full match text first if context was part of the regex
        full_match_text_lower = match.group(0).lower()

        if any(indicator in full_match_text_lower or indicator in surrounding_text for indicator in dob_indicators):
            return "[DATE_OF_BIRTH]"
        if any(indicator in full_match_text_lower or indicator in surrounding_text for indicator in expiry_indicators):
            return "[EXPIRY_DATE]"
        if any(indicator in full_match_text_lower or indicator in surrounding_text for indicator in issue_indicators):
            return "[ISSUE_DATE]"
        
        return "[DATE]"
        
    for pattern in date_patterns:
        censored_text = pattern.sub(replace_date, censored_text)
        
    return censored_text, count

def censor_passwords(text):
    count = 0
    # Patterns for passwords and tokens. Focus on contextual matches.
    # Be cautious with generic patterns to avoid false positives.
    pw_keywords = r'(?:password|passwd|pwd|passphrase|pass[\s_]?code|secret|credential|token|auth_key|private_key)'
    pw_patterns = [
        # Contextual: "password: mypass123", "token = '...' "
        re.compile(rf'(?i)\b{pw_keywords}\s*[:=]\s*["\']?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{{}};:\'",.<>\/?~`]{6,64})["\']?'),
        # XML/JSON like: <password>mypass</password> or "password": "mypass"
        re.compile(rf'(?i)<{pw_keywords}>([^<]+)</{pw_keywords}>'),
        re.compile(rf'(?i)["\']{pw_keywords}["\']\s*:\s*["\']([^"\']{{6,64}})["\']'),
        # JWT tokens (three Base64url segments separated by dots)
        re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?'), # Made signature optional for some token types
        # Very cautious generic pattern for strings that look like strong passwords IF NOT already part of a known structure.
        # This should run last or be heavily restricted. For now, let's rely on context.
        # re.compile(r'\b(?=(?:.*[A-Z]){1,})(?=(?:.*[a-z]){1,})(?=(?:.*\d){1,})(?=(?:.*[!@#$%^&*()_+=\-\[\]{{}};:\'",.<>\/?~`]){1,})[A-Za-z\d!@#$%^&*()_+=\-\[\]{{}};:\'",.<>\/?~`]{10,32}\b')
    ]
    
    censored_text = text
    
    def replace_password(match):
        nonlocal count
        
        # Captured group is usually group 1 for contextual patterns
        # For JWT, it's group 0
        password_value = ""
        if match.lastindex and match.lastindex > 0:
            password_value = match.group(1)
        else: # JWT or other full match
            password_value = match.group(0)

        if password_value.startswith("[") and password_value.endswith("]"):
            return match.group(0) # Return original full match

        # Avoid censoring very short "passwords" that might be parts of words if a loose pattern matched
        if len(password_value) < 6 and not password_value.startswith("eyJ"): # JWTs can be long
             return match.group(0)


        count += 1
        
        full_match_text_lower = match.group(0).lower()
        if "jwt" in full_match_text_lower or password_value.startswith("eyJ"):
            return "[JWT_TOKEN]"
        if "token" in full_match_text_lower:
            return "[AUTH_TOKEN]"
        if "secret" in full_match_text_lower or "key" in full_match_text_lower: # e.g. private_key
             return "[SECRET_OR_KEY]"
        return "[PASSWORD]"
        
    for pattern in pw_patterns:
        censored_text = pattern.sub(replace_password, censored_text)
        
    return censored_text, count
