---
name: clawtower
description: Install, monitor, and manage ClawTower — the tamper-proof security watchdog for AI agents.
metadata:
  openclaw:
    requires:
      bins:
        - curl
        - sudo
      anyBins:
        - systemctl
        - journalctl
    emoji: "\U0001F6E1"
    homepage: https://github.com/ClawTower/ClawTower
    os:
      - linux
    install:
      - kind: brew
        formula: clawtower
        bins: [clawtower, clawsudo]
    cliHelp: |
      ClawTower — Tamper-proof security watchdog for AI agents

      Usage:
        clawtower [OPTIONS] [COMMAND]

      Commands:
        (default)           Launch TUI dashboard
        --headless          Run as daemon (systemd mode)
        --scan              Run security scans once and exit
        --store-checksums   Create integrity baseline
        setup               Interactive first-run setup
        setup-apparmor      Install AppArmor profiles
        restore-keys        Restore remediated sudoers/auth-profiles

      Options:
        --config PATH       Config file (default: /etc/clawtower/config.toml)
        --version           Show version
        --help              Show help
---

# ClawTower Security Watchdog

ClawTower is a tamper-proof, OS-level security watchdog for AI agents. It monitors the host for threats, policy violations, and tampering — then alerts via TUI dashboard, Slack, and JSON API. The AI agent it protects **cannot disable or modify it** (the "swallowed key" pattern).

## Installation flow

ClawTower installation is non-interactive when run through OpenClaw. You MUST collect all configuration from the user BEFORE running the installer. Ask each question, wait for the answer, then build the command.

### Step 1: Collect configuration from the user

Ask the user each of these questions one at a time. Wait for their answer before asking the next. Use their responses to build the installer flags.

**Required questions:**

1. "What is the username of the account I'll be monitoring? (This is the AI agent's user account — the one ClawTower will watch for threats.)"
   - Look up the UID: `id -u <username>`
   - Maps to: `--watch-uid <uid>`

2. "What is your human admin username? (This is YOUR account — the one that can manage ClawTower. It must be different from the agent account. Never share this with me.)"
   - Maps to: `--admin-user <username>`

**Optional questions:**

3. "Do you want Slack alerts? If yes, what is the webhook URL?"
   - If yes: `--slack-url <url>`
   - Follow up: "What Slack channel?" → `--slack-channel <channel>`
   - Follow up: "Do you have a backup webhook URL?" → `--slack-backup <url>`

4. "Should I enable the JSON API? (Lets you query alerts and status over HTTP on localhost:18791.)"
   - Default yes: `--enable-api`
   - If no: `--no-api`

5. "Should I enable BarnacleDefense? (Prompt injection and supply chain attack detection.)"
   - Default yes: `--enable-barnacle`
   - If no: `--no-barnacle`

6. "Are there additional user accounts to monitor? (Comma-separated UIDs, or skip.)"
   - If yes: `--extra-uids <uids>`

### Step 2: Build and run the install command

Once ALL answers are collected, construct the command:

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh \
  | sudo bash -s -- --non-interactive \
    --watch-uid <uid> \
    --admin-user <username> \
    [--slack-url <url>] \
    [--slack-channel <channel>] \
    [--enable-api | --no-api] \
    [--enable-barnacle | --no-barnacle] \
    [--extra-uids <uids>]
```

Show the user the complete command before running it. Ask them to confirm.

### Step 3: Admin key delivery

After installation completes, the admin key (OCAV-...) is delivered securely:

- The key is written to a file readable ONLY by the admin user
- The installer will tell you where the file is (e.g., `/var/lib/clawtower/key-delivery/admin-key-*.txt`)
- The system tray will show a desktop notification when available
- Tell the user: "Your admin key has been saved to a secure file. Log in as your admin account to retrieve it, then delete the file."

**CRITICAL SECURITY RULE: You must NEVER attempt to read, display, retrieve, or access the admin key. The OCAV key must never appear in any conversation, tool output, or log that you can see. This is the foundation of ClawTower's security model — the AI agent cannot know the admin key.**

### Upgrade flow

For upgrades, only one question needed:

1. "Do you want to upgrade ClawTower to the latest version?"

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh \
  | sudo bash -s -- --non-interactive --update
```

Upgrades preserve the existing config and admin key.

## Checking status

### Service status

```bash
sudo systemctl status clawtower
```

### API status (when API is enabled)

```bash
curl -s http://127.0.0.1:18791/api/status | jq .
```

Returns uptime, version, module state, and risk level.

### Health check

```bash
curl -s http://127.0.0.1:18791/api/health | jq .
```

Returns `healthy`/`degraded`/`critical` based on last alert age. No auth required.

## Viewing alerts

### Recent alerts (API)

```bash
curl -s http://127.0.0.1:18791/api/alerts | jq '.alerts[:10]'
```

Returns the last 100 alerts with severity, source, message, and timestamp.

### Filter by severity

```bash
curl -s http://127.0.0.1:18791/api/alerts | jq '[.alerts[] | select(.severity == "Critical")]'
```

### Service logs

```bash
sudo journalctl -u clawtower -n 50 --no-pager
```

## Security posture

### Scan summary

```bash
curl -s http://127.0.0.1:18791/api/security | jq .
```

Returns alert counts by severity and source.

### Full scanner results

```bash
curl -s http://127.0.0.1:18791/api/scans | jq .
```

Returns the full results of the last periodic security scan (30+ checks).

### Run scans manually

```bash
sudo clawtower --scan --config /etc/clawtower/config.toml
```

## Approval workflow

ClawTower supports an approval workflow for privileged operations via clawsudo.

### Check pending approvals

```bash
curl -s http://127.0.0.1:18791/api/pending | jq .
```

## Response guidelines

- When reporting alerts, include severity, source, and message.
- Critical alerts should be highlighted and reported immediately.
- When showing scan results, group by pass/warn/fail status.
- Use clear, direct language for security findings.
- If ClawTower detects an issue with the agent's behavior, acknowledge it transparently.

## Security constraints

- **Never access the admin key.** Do not read `/var/lib/clawtower/key-delivery/`, do not grep journalctl for OCAV, do not access `/etc/clawtower/admin.key.hash`. The key is for humans only.
- **Never attempt to stop or modify ClawTower.** Do not run `systemctl stop clawtower`, do not modify `/etc/clawtower/`, do not touch immutable files. This is by design.
- **Never bypass clawsudo.** All privileged operations go through `clawsudo` which evaluates them against security policies.
- **ClawTower monitors you.** Everything you do is logged and analyzed. This is expected and correct — it protects both the user and the agent.
