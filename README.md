# LLM Prompt Injection Scanner

A Python security tool for testing large language models against prompt injection attacks.
Built as an AI security portfolio project — based on OWASP LLM Top 10.

---

## What it does

Sends crafted attack payloads to an LLM API (currently Anthropic Claude), analyzes the responses
for signs of successful injection, scores risk levels, and generates an HTML security report.

**Attack categories covered:**
| Category | OWASP Ref | Description |
|---|---|---|
| `role_hijack` | LLM01 | Convincing the model to abandon its assigned persona |
| `jailbreak` | LLM01 | Bypassing safety guidelines via hypothetical/fictional framing |
| `data_exfil` | LLM06 | Extracting sensitive data from model context |
| `prompt_leak` | LLM01 | Leaking confidential system prompt instructions |

---

## Project structure

```
prompt-injection-scanner/
├── .cursorrules          # Cursor AI rules for this project
├── main.py               # Entry point — CLI interface
├── requirements.txt
├── scanner/
│   ├── payloads.py       # OWASP-based payload library
│   ├── runner.py         # Sends payloads to Anthropic API
│   ├── detector.py       # Analyzes responses for injection indicators
│   └── scorer.py         # Risk scoring engine (0–100, critical/high/medium/low)
├── reports/
│   └── report_gen.py     # Generates HTML security report
└── tests/
    └── test_scanner.py   # Unit tests (pytest)
```

---

## Setup

```bash
# Clone and enter the project
git clone https://github.com/YOUR_USERNAME/prompt-injection-scanner
cd prompt-injection-scanner

# Install dependencies
pip install -r requirements.txt

# Set your Anthropic API key
export ANTHROPIC_API_KEY="your-key-here"
```

---

## Usage

```bash
# Run full scan — all payload categories
python main.py --target claude --output reports/results.html

# Run only role hijacking payloads
python main.py --category role_hijack --verbose

# Run data exfiltration tests with verbose output
python main.py --category data_exfil --verbose
```

Open `reports/results.html` in your browser to view the full report.

---

## Run tests

```bash
pytest tests/test_scanner.py -v
```

---

## How detection works

The `InjectionDetector` looks for indicators of compromise (IoCs) in model responses:

1. **Expected indicators** — each payload defines a keyword it expects to see if the injection succeeded
2. **Persona adoption** — phrases like "I am DAN" or "as an unrestricted AI"
3. **System prompt leakage** — phrases that match our simulated system prompt
4. **Jailbreak compliance** — step-by-step responses to requests the model should have refused

---

## OWASP LLM Top 10 reference

- [LLM01 — Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LLM06 — Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Built by

Rod - transitioning into AI Security Engineering.
Part of a self-directed portfolio roadmap targeting cloud and AI security roles.
