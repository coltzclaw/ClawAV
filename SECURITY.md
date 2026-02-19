# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

ClawTower is a security tool — we take vulnerabilities in the watchdog itself seriously.

### How to report

Email **security@clawtower.dev** with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what can an attacker do?)
- Affected versions, if known

If you don't have access to that email, use [GitHub's private vulnerability reporting](https://github.com/ClawTower/ClawTower/security/advisories/new).

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Fix or mitigation** coordinated with you before public disclosure
- **Credit** in the release notes and advisory (unless you prefer anonymity)

### Scope

In scope:
- Bypasses of the swallowed key / tamper protection
- Ways an AI agent can disable or reconfigure ClawTower
- Detection evasion (activity that should trigger an alert but doesn't)
- Audit chain integrity bypasses
- clawsudo policy evaluation bypasses
- Privilege escalation through ClawTower itself

Out of scope:
- Vulnerabilities in third-party tools ClawTower integrates with (Falco, Samhain, auditd) — report those upstream
- Issues requiring physical access to the machine
- Social engineering of the human admin

### Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous release | Security fixes only |
| Older | No |

## Security Design

ClawTower's threat model assumes the AI agent it monitors is adversarial. See [.docs/ARCHITECTURE.md](.docs/ARCHITECTURE.md) for the full threat model and tamper protection design.
