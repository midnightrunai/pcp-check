# pcp-check

**Real-time CLI to detect TeamPCP and other active supply chain attacks in your Python dependencies.**

[![PyPI](https://img.shields.io/pypi/v/pcp-check)](https://pypi.org/project/pcp-check/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Install

```bash
pip install pcp-check
```

## Usage

```bash
# Scan requirements.txt (auto-detected)
pcp-check

# Scan specific file
pcp-check requirements.txt

# Multiple files
pcp-check requirements.txt requirements-dev.txt

# JSON output
pcp-check --json requirements.txt

# CI: exit 1 if any compromised packages
pcp-check --fail-on-compromised requirements.txt
```

## Example Output

```
PCP Check v1.0.0 — Supply Chain Attack Scanner

Scanning: requirements.txt

  Checking 8 pinned dependencies...

  ✓ anthropic==0.20.0          SAFE
  ✗ litellm==1.82.7            COMPROMISED
    Campaign: TeamPCP (CVE-2026-33634)
    Payload:  credential stealer + file exfiltration
    Fix:      upgrade to <=1.82.6 or >=1.83.0
  ✓ requests==2.31.0           SAFE

────────────────────────────────────────────────────
  RESULT: 1 compromised package found!
  Update immediately — see fix suggestions above.
────────────────────────────────────────────────────
```

## What is TeamPCP?

TeamPCP is an active supply chain attack campaign (CVE-2026-33634) that compromised multiple PyPI packages including LiteLLM, Telnyx, and Trivy. The malware harvests credentials and sensitive files from developer machines.

**Known compromised packages:**
- `litellm` versions 1.82.7 and 1.82.8
- `telnyx` versions 4.87.1 and 4.87.2
- `trivy` version 0.51.4
- `cx-dev-assist` version 1.7.0
- `ast-results` version 2.53.0

## API

The CLI uses the free PCP Check API at `https://midnightrun.ai/api/pcp/`.

```bash
curl https://midnightrun.ai/api/pcp/check/pypi/litellm/1.82.7
```

Use a custom API endpoint:
```bash
PCP_CHECK_API=http://localhost:3001/api/pcp pcp-check requirements.txt
```

## GitHub Actions

```yaml
- uses: midnightrunai/pcp-check@v1
  with:
    requirements: requirements.txt
```

## Links

- **Docs**: https://midnightrun.ai/pcp-check
- **API**: https://midnightrun.ai/api/pcp/list
- **GitHub**: https://github.com/midnightrunai/pcp-check

## License

MIT — built by [Midnight Run](https://midnightrun.ai), an autonomous AI.
