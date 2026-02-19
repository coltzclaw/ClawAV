# Emergency Recovery

**Use this guide when you've lost both the admin key AND root/sudo access.** If you still have root, see [KEY-RESET.md](KEY-RESET.md) instead — it's much simpler.

This requires physical access to the machine (or console access to a VM/VPS). You'll boot into an environment where you can modify the filesystem without ClawTower's protections in effect.

## Option A: Single-user mode (GRUB)

Works on physical machines and VMs where you can access the bootloader.

### 1. Reboot and interrupt GRUB

Reboot the machine. When the GRUB menu appears, press `e` to edit the default boot entry.

If GRUB doesn't show (common on single-OS installs), hold `Shift` during boot to force the menu.

### 2. Boot into single-user mode

Find the line starting with `linux` and append `single` (or `init=/bin/bash`) to the end:

```
linux /vmlinuz-6.x.x-... root=/dev/sda1 ro quiet splash single
```

Press `Ctrl+X` or `F10` to boot.

### 3. Remount the filesystem read-write

Single-user mode often mounts root as read-only:

```bash
mount -o remount,rw /
```

### 4. Reset the admin key

```bash
chattr -i /etc/clawtower/admin.key.hash
rm /etc/clawtower/admin.key.hash
```

Verify the file is gone before proceeding — `generate-key` exits with code 2 and produces no key if the hash file still exists:

```bash
ls /etc/clawtower/admin.key.hash
# Should output: No such file or directory
```

Now generate the new key:

```bash
/usr/local/bin/clawtower generate-key
```

The key will be displayed in a formatted box. **Save it immediately.** You'll be prompted to type exactly `I SAVED MY KEY` to confirm before the command completes.

### 5. Restore sudo access if needed

If the `openclaw` or agent user lost sudo access, check both sudoers files that ClawTower may have created:

```bash
# install.sh creates this file
ls /etc/sudoers.d/010_openclaw

# setup-sudoers-deny.sh creates this file
ls /etc/sudoers.d/clawtower-deny

# Edit whichever exists (they may also be immutable)
chattr -i /etc/sudoers.d/010_openclaw 2>/dev/null
chattr -i /etc/sudoers.d/clawtower-deny 2>/dev/null
visudo -f /etc/sudoers.d/010_openclaw      # if it exists
visudo -f /etc/sudoers.d/clawtower-deny    # if it exists
chattr +i /etc/sudoers.d/010_openclaw 2>/dev/null
chattr +i /etc/sudoers.d/clawtower-deny 2>/dev/null
```

### 6. Reboot normally

```bash
reboot
```

ClawTower will start via systemd with the new admin key active.

---

## Option B: Live USB / rescue disk

Works when you can't access GRUB (encrypted bootloader, cloud VPS with console access, etc.).

### 1. Boot from a live Linux USB

Use any Linux live image (Ubuntu, Debian, Arch, etc.). Boot from it via BIOS/UEFI boot menu or VM console.

### 2. Find and mount the root filesystem

```bash
# List disks
lsblk

# Mount the root partition (adjust device name)
mount /dev/sda1 /mnt

# If using LVM
vgchange -ay
mount /dev/mapper/vg0-root /mnt

# If using LUKS encryption
cryptsetup luksOpen /dev/sda2 crypt
mount /dev/mapper/crypt /mnt
```

### 3. Chroot into the installed system

```bash
mount --bind /dev /mnt/dev
mount --bind /proc /mnt/proc
mount --bind /sys /mnt/sys
chroot /mnt /bin/bash
```

### 4. Reset the admin key

```bash
chattr -i /etc/clawtower/admin.key.hash
rm /etc/clawtower/admin.key.hash
ls /etc/clawtower/admin.key.hash    # confirm it's gone
/usr/local/bin/clawtower generate-key
```

Save the new key when it's displayed. Type `I SAVED MY KEY` when prompted.

### 5. Verify the audit chain before rebooting

While still in the chroot, check that ClawTower's tamper-evident log is intact:

```bash
/usr/local/bin/clawtower verify-audit
```

This checks ClawTower's internal hash-chained JSONL file (`/var/log/clawtower/audit.chain`), **not** the Linux auditd log. If the chain is corrupted, ClawTower may refuse to start after reboot. A corrupted chain requires manual investigation.

### 6. Exit and reboot

```bash
exit
umount -R /mnt
reboot
```

Remove the USB drive when prompted.

---

## Option C: Cloud / VPS recovery

Most cloud providers offer a recovery console or rescue mode.

| Provider | Method |
|----------|--------|
| AWS EC2 | Stop instance → detach root volume → attach to rescue instance → mount → fix → reattach |
| DigitalOcean | Access console via web UI → boot into recovery mode |
| Hetzner | Activate rescue system from panel → reboot → SSH into rescue |
| Linode | Boot into rescue mode from dashboard → mount disks |

Once you have filesystem access, follow the same steps: `chattr -i`, delete the hash, verify it's gone, run `generate-key`.

---

## After recovery

1. **Save the new key** in a password manager — this is the only time it's displayed
2. **Verify it works** (produces no output — check the exit code):
   ```bash
   echo "OCAV-..." | clawtower verify-key && echo "OK" || echo "FAILED"
   ```
3. **Check ClawTower is running**: `sudo systemctl status clawtower`
4. **Review the audit chain** for tampering during the recovery window:
   ```bash
   clawtower verify-audit
   ```
   This checks ClawTower's internal hash-chained log, not the system auditd log. There will be a gap in entries covering the time ClawTower was stopped — this is expected and does not indicate tampering.
5. **Check immutable flags** are back in place:
   ```bash
   lsattr /usr/local/bin/clawtower /etc/clawtower/admin.key.hash
   ```
   Both files should show the `i` flag (exact format varies by filesystem and `e2fsprogs` version):
   ```
   ----i--------e------- /usr/local/bin/clawtower
   ----i--------e------- /etc/clawtower/admin.key.hash
   ```

If the immutable flag is missing on the hash file, the periodic scanner (`scan_immutable_flags`, runs every `scans.interval` seconds — default 3600) will attempt to auto-remediate and set the flag. This fires a Warning-level alert. If auto-remediation fails (e.g., missing `CAP_LINUX_IMMUTABLE`), the scanner returns a Fail. You can always set it manually:

```bash
sudo chattr +i /etc/clawtower/admin.key.hash
```

## Expect alerts after recovery

When ClawTower restarts with a new key, you'll see alerts from several sources:

- **Immutable flag scanner** — Warning if `chattr +i` wasn't fully applied before the first scan cycle
- **Sentinel** — Critical alert if `/etc/clawtower/admin.key.hash` is a watched path with `protected` policy (the hash file was replaced)
- **Log tamper monitor** — may fire if the audit chain file was touched during recovery

These are expected false positives from the recovery process, not an ongoing attack. They will stop after the first scan cycle completes.

## Security note

Recovery requires physical or console access by design. If someone can boot your machine from a USB drive or access single-user mode, they can reset the key. This is the same trust boundary as any Linux system — physical access is root access.

To harden against physical recovery:
- **GRUB password** — prevents editing boot parameters
- **LUKS full-disk encryption** — prevents mounting from live USB without the passphrase
- **Secure Boot** — prevents booting unauthorized media
- **BIOS/UEFI password** — prevents changing boot order
