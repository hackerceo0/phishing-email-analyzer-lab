# Phishing Email Analyzer

<div align="center">

A Python-based tool for analyzing suspicious emails. Extracts headers, URLs, attachments, and identifies indicators of compromise (IOCs) commonly found in phishing attacks.

 </div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow)

 </div>

## Demo

### Phishing Detection
![Phishing Analyzer Demo](screenshots/phishing-email-analyzer.png)

## Features

- **Header Analysis**: Extracts and analyzes email headers (From, To, Subject, Reply-To, etc.)
- **SPF/DKIM/DMARC Checks**: Identifies authentication results
- **URL Extraction**: Pulls all URLs from email body and identifies suspicious patterns
- **Attachment Detection**: Lists attachments and flags dangerous file types
- **IOC Extraction**: Automatically extracts indicators of compromise
- **Suspicion Scoring**: Rates emails based on multiple risk factors

## Installation

```bash
git clone https://github.com/Rootless-Ghost/Phishing-Analyzer.git
cd Phishing-Analyzer
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a single email file
python src/phishing_analyzer.py --input samples/suspicious_email.eml

# Analyze with verbose output
python src/phishing_analyzer.py --input samples/suspicious_email.eml --verbose

# Output results to JSON
python src/phishing_analyzer.py --input samples/suspicious_email.eml --output json
```

## Project Structure

```
phishing-analyzer/
├── src/
│   └── phishing_analyzer.py    # Main analysis script
├── samples/                     # Sample .eml files for testing
├── output/                      # Generated reports
├── tests/                       # Unit tests
├── requirements.txt
└── README.md
```

## What It Detects

| Indicator | Risk Level | Description |
|-----------|------------|-------------|
| Mismatched From/Reply-To | High | Sender and reply address don't match |
| Suspicious URLs | High | URLs with IP addresses, lookalike domains, URL shorteners |
| Dangerous Attachments | High | .exe, .js, .vbs, .scr, .bat files |
| Urgency Keywords | Medium | "URGENT", "ACT NOW", "VERIFY IMMEDIATELY" |
| SPF/DKIM Fail | Medium | Email authentication failures |
| External Links | Low | Links to external domains |

## Roadmap

- [x] Project setup
- [x] Email header parsing
- [x] URL extraction and analysis
- [x] Attachment detection
- [x] Suspicion scoring
- [ ] VirusTotal API integration
- [ ] HTML report generation
- [ ] Batch analysis mode

## Author

**RootlessGhost**

Junior Penetration Tester | SOC Analyst in Training

## License

MIT License - See [LICENSE](LICENSE) for details

---

<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

</div>
