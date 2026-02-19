# Admin Key Reset

**Prerequisite:** You have root or sudo access on the machine. If you don't, see [RECOVERY.md](RECOVERY.md).

The admin key (`OCAV-` + 64 hex characters) is generated once and stored only as an Argon2 hash at `/etc/clawtower/admin.key.hash`. The hash file is immutable (`chattr +i`), so even root can't modify it without removing the flag first.

If you've lost the key, here's how to generate a new one.

## Steps

### 1. Stop ClawTower

```bash
sudo systemctl stop clawtower
```

### 2. Remove the immutable flag from the hash file

```bash
sudo chattr -i /etc/clawtower/admin.key.hash
```

If `chattr` fails because `CAP_LINUX_IMMUTABLE` was dropped from the capability bounding set (via `pam_cap`), use the systemd-run fallback, which runs in PID 1's scope with full capabilities:

```bash
sudo systemd-run --wait --collect --quiet chattr -i /etc/clawtower/admin.key.hash
```

### 3. Delete the old hash

```bash
sudo rm /etc/clawtower/admin.key.hash
```

Verify it's actually gone:

```bash
ls /etc/clawtower/admin.key.hash
# Should output: No such file or directory
```

This step is required. `generate-key` checks whether the hash file exists and **will not overwrite it** — it exits with code 2 and produces no key output if the file is still present.

### 4. Generate a new key

```bash
sudo clawtower generate-key
```

This will:
- Generate a new 256-bit key with cryptographically secure randomness
- Display it in a formatted box — **save it immediately**
- Prompt you to type exactly `I SAVED MY KEY` to confirm
- Write the Argon2 hash to `/etc/clawtower/admin.key.hash`
- Set `chattr +i` on the new hash file automatically

**Exit codes:** `0` = new key generated. `2` = hash file already exists (nothing happened — go back to step 3). `1` = generation failed.

### 5. Restart ClawTower

```bash
sudo systemctl start clawtower
```

**Expect alerts on restart.** ClawTower may fire Warning-level alerts from the immutable flag scanner if it runs before the new `chattr +i` is detected. This is normal and will resolve on the next scan cycle.

### 6. Verify the new key works

```bash
echo "OCAV-your-new-key-here" | clawtower verify-key && echo "OK" || echo "FAILED"
```

`verify-key` produces no output — it communicates success or failure only through exit codes. Exit code `0` = key verified, `1` = verification failed. You can also use the `--key` flag:

```bash
clawtower verify-key --key "OCAV-your-new-key-here" && echo "OK" || echo "FAILED"
```

## What gets invalidated

- The old key is permanently invalid — there is no way to recover it
- Any scripts or password managers storing the old key need to be updated
- The admin socket will accept the new key immediately after restart
- The 3-failure rate limiter resets on restart (it is in-memory only, no carry-over)

## Quick reference

```bash
# All steps in sequence
sudo systemctl stop clawtower
sudo chattr -i /etc/clawtower/admin.key.hash
sudo rm /etc/clawtower/admin.key.hash
sudo clawtower generate-key          # exit code 2 = hash wasn't deleted, try again
sudo systemctl start clawtower
```
