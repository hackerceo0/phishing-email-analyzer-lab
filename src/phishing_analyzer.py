#!/usr/bin/env python3
"""
Phishing Email Analyzer
Author: RootlessGhost
Description: Analyzes suspicious emails for phishing indicators and extracts IOCs.
"""

import argparse
import sys
import re
import email
import json
from pathlib import Path
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from datetime import datetime


# Suspicious patterns and keywords
SUSPICIOUS_EXTENSIONS = ['.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.jar', '.msi', '.dll', '.zip', '.rar', '.7z']
URGENCY_KEYWORDS = ['urgent', 'immediate', 'act now', 'verify', 'suspended', 'locked', 'unauthorized', 'confirm your', 'update your', 'click here', 'expire', 'limited time']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im']
SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.click', '.link', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw']


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer - Detect suspicious emails and extract IOCs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_analyzer.py --input suspicious_email.eml
  python phishing_analyzer.py --input email.eml --output json
  python phishing_analyzer.py --input email.eml --verbose
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the .eml file to analyze"
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed analysis"
    )
    
    return parser.parse_args()


def print_banner():
    """Print the tool banner."""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║       PHISHING EMAIL ANALYZER v1.0            ║
    ║         Suspicious Email Detection            ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)


def load_email(filepath: str) -> email.message.EmailMessage:
    """Load and parse an .eml file."""
    path = Path(filepath)
    
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    
    if not path.suffix.lower() == '.eml':
        print(f"[WARNING] File may not be an .eml file: {filepath}")
    
    with open(path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    return msg


def extract_headers(msg: email.message.EmailMessage) -> dict:
    """Extract relevant email headers."""
    headers = {
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'message_id': msg.get('Message-ID', ''),
        'x_originating_ip': msg.get('X-Originating-IP', ''),
        'received': msg.get_all('Received', []),
        'authentication_results': msg.get('Authentication-Results', ''),
        'spf': '',
        'dkim': '',
        'dmarc': ''
    }
    
    # Parse authentication results
    auth_results = headers['authentication_results']
    if auth_results:
        if 'spf=pass' in auth_results.lower():
            headers['spf'] = 'pass'
        elif 'spf=fail' in auth_results.lower():
            headers['spf'] = 'fail'
        elif 'spf=softfail' in auth_results.lower():
            headers['spf'] = 'softfail'
        
        if 'dkim=pass' in auth_results.lower():
            headers['dkim'] = 'pass'
        elif 'dkim=fail' in auth_results.lower():
            headers['dkim'] = 'fail'
        
        if 'dmarc=pass' in auth_results.lower():
            headers['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_results.lower():
            headers['dmarc'] = 'fail'
    
    return headers


def extract_email_address(header_value: str) -> str:
    """Extract just the email address from a header value."""
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    return match.group(0) if match else header_value


def extract_domain(email_addr: str) -> str:
    """Extract domain from an email address."""
    if '@' in email_addr:
        return email_addr.split('@')[-1].lower()
    return ''


def get_email_body(msg: email.message.EmailMessage) -> str:
    """Extract the email body text."""
    body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                try:
                    body += part.get_content()
                except:
                    pass
            elif content_type == 'text/html':
                try:
                    body += part.get_content()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            body = str(msg.get_payload(decode=True))
    
    return body


def extract_urls(body: str) -> list:
    """Extract all URLs from the email body."""
    # Match URLs
    url_pattern = r'https?://[^\s<>"\'}\])]+'
    urls = re.findall(url_pattern, body)
    
    # Also look for href attributes
    href_pattern = r'href=["\']([^"\']+)["\']'
    hrefs = re.findall(href_pattern, body)
    
    all_urls = list(set(urls + [h for h in hrefs if h.startswith('http')]))
    return all_urls


def analyze_url(url: str) -> dict:
    """Analyze a single URL for suspicious indicators."""
    result = {
        'url': url,
        'domain': '',
        'suspicious': False,
        'reasons': []
    }
    
    try:
        parsed = urlparse(url)
        result['domain'] = parsed.netloc
        
        # Check for IP address instead of domain
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, parsed.netloc):
            result['suspicious'] = True
            result['reasons'].append("URL uses IP address instead of domain")
        
        # Check for URL shorteners
        for shortener in URL_SHORTENERS:
            if shortener in parsed.netloc.lower():
                result['suspicious'] = True
                result['reasons'].append(f"Uses URL shortener: {shortener}")
        
        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if parsed.netloc.lower().endswith(tld):
                result['suspicious'] = True
                result['reasons'].append(f"Suspicious TLD: {tld}")
        
        # Check for lookalike characters
        lookalikes = {'0': 'o', '1': 'l', '5': 's', '@': 'a'}
        domain_lower = parsed.netloc.lower()
        common_targets = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'bank']
        for target in common_targets:
            # Simple check - could be more sophisticated
            if target not in domain_lower and any(c in domain_lower for c in target[:4]):
                # Might be a lookalike, flag for review
                pass
        
        # Check for excessive subdomains
        if parsed.netloc.count('.') > 3:
            result['suspicious'] = True
            result['reasons'].append("Excessive subdomains")
        
        # Check for @ in URL (credential harvesting trick)
        if '@' in url:
            result['suspicious'] = True
            result['reasons'].append("Contains @ symbol (possible URL obfuscation)")
        
    except Exception as e:
        result['reasons'].append(f"Failed to parse: {e}")
    
    return result


def extract_attachments(msg: email.message.EmailMessage) -> list:
    """Extract attachment information."""
    attachments = []
    
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename:
                ext = Path(filename).suffix.lower()
                is_dangerous = ext in SUSPICIOUS_EXTENSIONS
                
                attachments.append({
                    'filename': filename,
                    'extension': ext,
                    'dangerous': is_dangerous,
                    'content_type': part.get_content_type(),
                    'size': len(part.get_payload())
                })
    
    return attachments


def check_urgency_keywords(body: str, subject: str) -> list:
    """Check for urgency/pressure keywords."""
    found_keywords = []
    combined_text = (body + ' ' + subject).lower()
    
    for keyword in URGENCY_KEYWORDS:
        if keyword in combined_text:
            found_keywords.append(keyword)
    
    return found_keywords


def calculate_suspicion_score(analysis: dict) -> int:
    """Calculate overall suspicion score (0-100)."""
    score = 0
    
    # Header checks
    if analysis['header_issues']['from_reply_mismatch']:
        score += 25
    if analysis['header_issues']['spf_fail']:
        score += 20
    if analysis['header_issues']['dkim_fail']:
        score += 15
    
    # URL checks
    suspicious_urls = [u for u in analysis['urls'] if u['suspicious']]
    score += min(len(suspicious_urls) * 10, 30)
    
    # Attachment checks
    dangerous_attachments = [a for a in analysis['attachments'] if a['dangerous']]
    score += min(len(dangerous_attachments) * 15, 30)
    
    # Urgency keywords
    score += min(len(analysis['urgency_keywords']) * 5, 15)
    
    return min(score, 100)


def analyze_email(msg: email.message.EmailMessage) -> dict:
    """Perform full analysis on an email."""
    headers = extract_headers(msg)
    body = get_email_body(msg)
    
    # Extract email addresses
    from_email = extract_email_address(headers['from'])
    reply_to_email = extract_email_address(headers['reply_to']) if headers['reply_to'] else ''
    
    # Header issues
    header_issues = {
        'from_reply_mismatch': False,
        'spf_fail': headers['spf'] in ['fail', 'softfail'],
        'dkim_fail': headers['dkim'] == 'fail',
        'dmarc_fail': headers['dmarc'] == 'fail'
    }
    
    # Check From/Reply-To mismatch
    if reply_to_email and from_email:
        from_domain = extract_domain(from_email)
        reply_domain = extract_domain(reply_to_email)
        if from_domain and reply_domain and from_domain != reply_domain:
            header_issues['from_reply_mismatch'] = True
    
    # Extract and analyze URLs
    urls = extract_urls(body)
    url_analysis = [analyze_url(url) for url in urls]
    
    # Extract attachments
    attachments = extract_attachments(msg)
    
    # Check urgency keywords
    urgency_keywords = check_urgency_keywords(body, headers['subject'])
    
    # Build analysis result
    analysis = {
        'headers': headers,
        'header_issues': header_issues,
        'urls': url_analysis,
        'attachments': attachments,
        'urgency_keywords': urgency_keywords,
        'body_preview': body[:500] if body else ''
    }
    
    analysis['suspicion_score'] = calculate_suspicion_score(analysis)
    
    return analysis


def get_risk_level(score: int) -> str:
    """Convert score to risk level."""
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def output_terminal(analysis: dict, verbose: bool = False):
    """Output results to terminal."""
    score = analysis['suspicion_score']
    risk = get_risk_level(score)
    
    # Risk level coloring
    if risk == "HIGH":
        risk_display = f"\033[91m{risk}\033[0m"
        score_display = f"\033[91m{score}/100\033[0m"
    elif risk == "MEDIUM":
        risk_display = f"\033[93m{risk}\033[0m"
        score_display = f"\033[93m{score}/100\033[0m"
    else:
        risk_display = f"\033[92m{risk}\033[0m"
        score_display = f"\033[92m{score}/100\033[0m"
    
    print("\n" + "=" * 60)
    print("                    ANALYSIS RESULTS")
    print("=" * 60)
    
    # Basic info
    print(f"\n  Subject:    {analysis['headers']['subject']}")
    print(f"  From:       {analysis['headers']['from']}")
    print(f"  To:         {analysis['headers']['to']}")
    print(f"  Date:       {analysis['headers']['date']}")
    
    print("\n" + "-" * 60)
    print(f"  SUSPICION SCORE: {score_display}")
    print(f"  RISK LEVEL:      {risk_display}")
    print("-" * 60)
    
    # Findings
    print("\n  FINDINGS:\n")
    
    findings_count = 0
    
    # Header issues
    if analysis['header_issues']['from_reply_mismatch']:
        print(f"  \033[91m[!]\033[0m From/Reply-To domain mismatch (possible spoofing)")
        findings_count += 1
    
    if analysis['header_issues']['spf_fail']:
        print(f"  \033[91m[!]\033[0m SPF check failed")
        findings_count += 1
    
    if analysis['header_issues']['dkim_fail']:
        print(f"  \033[91m[!]\033[0m DKIM check failed")
        findings_count += 1
    
    # Suspicious URLs
    suspicious_urls = [u for u in analysis['urls'] if u['suspicious']]
    if suspicious_urls:
        print(f"\n  \033[91m[!]\033[0m Suspicious URLs detected: {len(suspicious_urls)}")
        for url_info in suspicious_urls:
            print(f"      - {url_info['domain']}")
            for reason in url_info['reasons']:
                print(f"        └─ {reason}")
        findings_count += len(suspicious_urls)
    
    # Dangerous attachments
    dangerous = [a for a in analysis['attachments'] if a['dangerous']]
    if dangerous:
        print(f"\n  \033[91m[!]\033[0m Dangerous attachments: {len(dangerous)}")
        for att in dangerous:
            print(f"      - {att['filename']} ({att['extension']})")
        findings_count += len(dangerous)
    
    # Urgency keywords
    if analysis['urgency_keywords']:
        print(f"\n  \033[93m[!]\033[0m Urgency/pressure keywords found: {len(analysis['urgency_keywords'])}")
        print(f"      {', '.join(analysis['urgency_keywords'][:5])}")
        findings_count += 1
    
    if findings_count == 0:
        print("  \033[92m[+]\033[0m No major suspicious indicators found")
    
    # Verbose output
    if verbose:
        print("\n" + "-" * 60)
        print("  DETAILED INFO:\n")
        
        print(f"  Reply-To:   {analysis['headers']['reply_to']}")
        print(f"  Return-Path: {analysis['headers']['return_path']}")
        print(f"  Message-ID: {analysis['headers']['message_id']}")
        
        if analysis['headers']['x_originating_ip']:
            print(f"  Originating IP: {analysis['headers']['x_originating_ip']}")
        
        print(f"\n  Total URLs found: {len(analysis['urls'])}")
        print(f"  Total attachments: {len(analysis['attachments'])}")
        
        if analysis['attachments']:
            print("\n  All attachments:")
            for att in analysis['attachments']:
                status = "\033[91m[DANGEROUS]\033[0m" if att['dangerous'] else "[OK]"
                print(f"      {status} {att['filename']}")
    
    print("\n" + "=" * 60)
    print("[*] Analysis complete.")


def output_json(analysis: dict):
    """Output results as JSON."""
    # Convert to JSON-serializable format
    output = {
        'suspicion_score': analysis['suspicion_score'],
        'risk_level': get_risk_level(analysis['suspicion_score']),
        'subject': analysis['headers']['subject'],
        'from': analysis['headers']['from'],
        'to': analysis['headers']['to'],
        'date': analysis['headers']['date'],
        'reply_to': analysis['headers']['reply_to'],
        'header_issues': analysis['header_issues'],
        'suspicious_urls': [u for u in analysis['urls'] if u['suspicious']],
        'total_urls': len(analysis['urls']),
        'dangerous_attachments': [a for a in analysis['attachments'] if a['dangerous']],
        'total_attachments': len(analysis['attachments']),
        'urgency_keywords': analysis['urgency_keywords']
    }
    
    print(json.dumps(output, indent=2))


def main():
    """Main entry point."""
    print_banner()
    
    args = parse_arguments()
    
    print(f"[*] Loading email: {args.input}")
    msg = load_email(args.input)
    
    print("[*] Analyzing email...")
    analysis = analyze_email(msg)
    
    if args.output == "json":
        output_json(analysis)
    else:
        output_terminal(analysis, args.verbose)


if __name__ == "__main__":
    main()
