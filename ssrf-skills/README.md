# SSRF Skill for Claude

A Claude skill for Server-Side Request Forgery (SSRF) security testing — detection, exploitation, bypass techniques, and remediation.

## Overview

This skill enables Claude to assist with intelligent SSRF testing, covering:

- Basic SSRF discovery across all injection surfaces
- Blind SSRF detection via out-of-band (OAST) callbacks
- Cloud metadata exploitation (AWS, GCP, Azure, DigitalOcean)
- Internal network mapping and port scanning via SSRF
- Filter bypass (IP obfuscation, DNS rebinding, redirect chains, URL parser confusion)
- Protocol abuse (`file://`, `gopher://`, `dict://`)
- Post-exploitation with stolen credentials
- Developer remediation guidance

## Prerequisites

- Claude Desktop or Claude Code
- Python 3.7+ (for `ssrf_helper.py`)
- Appropriate authorization to test target systems

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/ssrf-skill
mkdir -p ~/.claude/skills
cp -r ssrf-skill ~/.claude/skills/
```

## Usage

Ask Claude naturally:

- "Help me test for SSRF on this URL parameter"
- "How do I bypass 127.0.0.1 blocklist in SSRF"
- "Generate AWS IMDS SSRF payloads"
- "Detect blind SSRF with out-of-band"
- "Build gopher:// payload for Redis via SSRF"

## Helper Script

```bash
python3 ssrf_helper.py encode 169.254.169.254   # IP obfuscation variants
python3 ssrf_helper.py cloud                    # Cloud metadata payloads
python3 ssrf_helper.py payloads                 # All localhost/file payloads
python3 ssrf_helper.py probe 'https://target.com/fetch?url=FUZZ'
python3 ssrf_helper.py redirect 8888            # Start redirect server
python3 ssrf_helper.py gopher-redis 127.0.0.1 6379 INFO
python3 ssrf_helper.py portscan 10.0.0.1
```

## Files

```
ssrf-skill/
├── SKILL.md                      # Main skill instructions for Claude
├── ssrf_helper.py                # Payload generator & utility scripts
├── README.md                     # This file
└── resources/
    └── bypass-techniques.md      # Deep reference for filter bypasses
```

## Safety & Ethics

**IMPORTANT:** For authorized security testing only.

- Only test systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Respect applicable laws and regulations
- Do not use against production systems without authorization

Unauthorized testing is illegal and unethical.
