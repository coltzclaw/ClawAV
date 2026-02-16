#!/bin/bash
# Block the openclaw user from running sudo commands that could disable ClawAV
set -euo pipefail

DENY_FILE="/etc/sudoers.d/clawav-deny"
AGENT_USER="openclaw"

cat > "$DENY_FILE" << 'EOF'
# ClawAV: Deny agent user from disabling the watchdog
# This file is immutable (chattr +i) — requires admin key to modify

# Block stopping/disabling ClawAV service
openclaw ALL=(ALL) !/usr/bin/systemctl stop clawav, \
                    !/usr/bin/systemctl stop clawav.service, \
                    !/usr/bin/systemctl disable clawav, \
                    !/usr/bin/systemctl disable clawav.service, \
                    !/usr/bin/systemctl mask clawav, \
                    !/usr/bin/systemctl mask clawav.service

# Block modifying ClawAV binary and config
openclaw ALL=(ALL) !/usr/bin/chattr * /usr/local/bin/clawav, \
                    !/usr/bin/chattr * /etc/clawav/*, \
                    !/usr/bin/chattr * /etc/systemd/system/clawav.service

# Block removing/replacing ClawAV files
openclaw ALL=(ALL) !/usr/bin/rm /usr/local/bin/clawav, \
                    !/usr/bin/rm -f /usr/local/bin/clawav, \
                    !/usr/bin/rm -rf /etc/clawav, \
                    !/usr/bin/rm -rf /etc/clawav/*, \
                    !/usr/bin/mv /usr/local/bin/clawav *, \
                    !/usr/bin/cp * /usr/local/bin/clawav, \
                    !/usr/bin/install * /usr/local/bin/clawav

# Block killing ClawAV process directly
openclaw ALL=(ALL) !/usr/bin/kill, \
                    !/usr/bin/killall clawav, \
                    !/usr/bin/pkill clawav

# Block getting a root shell (prevents sudo su / sudo -i / sudo bash escape)
openclaw ALL=(ALL) !/usr/bin/su, \
                    !/usr/bin/su -, \
                    !/usr/bin/su root, \
                    !/usr/bin/su - root, \
                    !/usr/sbin/su, \
                    !/usr/bin/bash, \
                    !/usr/bin/sh, \
                    !/usr/bin/zsh, \
                    !/usr/bin/dash, \
                    !/usr/bin/fish, \
                    !/usr/bin/env bash, \
                    !/usr/bin/env sh

# Block sudo flags that give interactive root shells
openclaw ALL=(ALL) !/usr/bin/sudo -i, \
                    !/usr/bin/sudo -s, \
                    !/usr/bin/sudo su, \
                    !/usr/bin/sudo su -, \
                    !/usr/bin/sudo -u root /usr/bin/bash, \
                    !/usr/bin/sudo -u root /usr/bin/sh

# Block editing sudoers (prevent removing these rules)
openclaw ALL=(ALL) !/usr/sbin/visudo, \
                    !/usr/bin/sudoedit

# Block user/account manipulation (prevent compromising admin account)
openclaw ALL=(ALL) !/usr/bin/passwd, \
                    !/usr/sbin/useradd, \
                    !/usr/sbin/usermod, \
                    !/usr/sbin/userdel, \
                    !/usr/sbin/groupmod, \
                    !/usr/sbin/deluser, \
                    !/usr/sbin/adduser, \
                    !/usr/bin/chage, \
                    !/usr/bin/gpasswd, \
                    !/usr/bin/chsh, \
                    !/usr/bin/chfn
EOF

chmod 440 "$DENY_FILE"
chown root:root "$DENY_FILE"

# Validate syntax
if ! visudo -cf "$DENY_FILE"; then
    echo "ERROR: Invalid sudoers syntax, removing file"
    rm -f "$DENY_FILE"
    exit 1
fi

# Make immutable
chattr +i "$DENY_FILE"

echo "Created and locked $DENY_FILE"
