# Repository Security Guide for Ubuntu/Linux Mint

## Safe Baseline: Ubuntu

### sources.list (Ubuntu 22.04 "jammy" example)

```bash
# Ubuntu Official Repositories
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse

# Security updates
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
```

**Components Explained:**
- `main` - Officially supported open source software
- `restricted` - Proprietary drivers for devices
- `universe` - Community-maintained open source software
- `multiverse` - Software restricted by copyright/legal issues

**Repository Types:**
- `jammy` - Base release packages
- `jammy-updates` - Recommended updates (bugfixes, minor updates)
- `jammy-backports` - Newer versions of software (optional)
- `jammy-security` - Security patches (CRITICAL)

---

## Safe Baseline: Linux Mint

### sources.list (Linux Mint 21 "vanessa" example)

```bash
# Linux Mint repositories
deb http://packages.linuxmint.com vanessa main upstream import backport

# Ubuntu base repositories (based on jammy)
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse

# Ubuntu security updates
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
```

**Mint-Specific Components:**
- `main` - Linux Mint packages
- `upstream` - Upstream Ubuntu packages modified by Mint
- `import` - Packages imported from Ubuntu/Debian
- `backport` - Newer packages backported by Mint team

---

## GPG Key Security

### Safe Key Locations

**System Keys (Official):**
```
/usr/share/keyrings/ubuntu-archive-keyring.gpg
/usr/share/keyrings/linuxmint-keyring.gpg
```

**Legacy Keys:**
```
/etc/apt/trusted.gpg.d/*.gpg
```

### Verify Official Keyrings

```bash
# Ubuntu
dpkg -l | grep ubuntu-keyring

# Linux Mint
dpkg -l | grep linuxmint-keyring
```

### Modern vs Legacy Format

**Modern (Recommended):**
```bash
deb [signed-by=/usr/share/keyrings/example-archive-keyring.gpg] https://example.com/ubuntu jammy main
```

**Legacy (Still works):**
```bash
deb https://example.com/ubuntu jammy main
# Key in /etc/apt/trusted.gpg.d/
```

---

## Warning Signs: Suspicious Repositories

### RED FLAGS 🚩

1. **No HTTPS**
   ```bash
   deb http://suspicious-repo.com/ubuntu jammy main
   # Should be https:// for security
   ```

2. **Unknown domains**
   ```bash
   deb http://sketchy-packages.xyz jammy main
   # Not a known trusted source
   ```

3. **Unsigned or "allow-insecure"**
   ```bash
   deb [trusted=yes] http://unsigned.com jammy main
   # NEVER USE trusted=yes unless you know what you're doing
   ```

4. **Personal/Abandoned PPAs**
   ```bash
   deb http://ppa.launchpad.net/random-person/abandoned-ppa/ubuntu jammy main
   # Check PPA activity and reputation
   ```

5. **Duplicate entries**
   ```bash
   # Same repository listed multiple times
   # Could indicate malicious modification
   ```

---

## Common Safe Third-Party Repositories

### Official PPAs (Generally Safe)

```bash
# Google Chrome
deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main

# VSCode
deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main

# Docker
deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu jammy stable
```

**Why these are safer:**
- HTTPS connections
- Signed with GPG keys
- From reputable companies
- Actively maintained

---

## Cleaning Compromised Repositories

### Step-by-Step Cleanup

1. **Backup first:**
   ```bash
   sudo cp /etc/apt/sources.list /etc/apt/sources.list.backup
   sudo cp -r /etc/apt/sources.list.d /root/sources.list.d.backup
   ```

2. **Inspect sources.list:**
   ```bash
   cat /etc/apt/sources.list
   # Look for unknown domains or suspicious entries
   ```

3. **Check sources.list.d:**
   ```bash
   ls /etc/apt/sources.list.d/
   cat /etc/apt/sources.list.d/*.list
   # Remove any suspicious .list files
   ```

4. **Remove suspicious entries:**
   ```bash
   sudo rm /etc/apt/sources.list.d/suspicious-repo.list
   ```

5. **Reset to baseline:**
   ```bash
   # Use the repo_baseline_script.sh
   sudo ./repo_baseline_script.sh
   ```

6. **Update and verify:**
   ```bash
   sudo apt update
   # Check for errors or warnings
   ```

---

## Best Practices

### ✅ DO:

1. **Always backup before changes**
2. **Use HTTPS when available**
3. **Verify GPG signatures**
4. **Keep official keyrings updated**
5. **Document why you added each PPA**
6. **Periodically audit repositories**
7. **Remove unused PPAs**

### ❌ DON'T:

1. **Never use `trusted=yes` blindly**
2. **Don't add PPAs from unknown sources**
3. **Don't disable signature checking**
4. **Don't use HTTP for security updates**
5. **Don't keep abandoned PPAs**
6. **Don't ignore GPG key warnings**

---

## Common Codenames Reference

### Ubuntu
- 24.04 LTS - `noble`
- 22.04 LTS - `jammy`
- 20.04 LTS - `focal`
- 18.04 LTS - `bionic`

### Linux Mint
- 22 - `wilma` (based on noble)
- 21.3 - `virginia` (based on jammy)
- 21.2 - `victoria` (based on jammy)
- 21.1 - `vera` (based on jammy)
- 21 - `vanessa` (based on jammy)
- 20.3 - `una` (based on focal)

---

## Emergency Recovery

If `apt update` fails after changes:

```bash
# 1. Check for syntax errors
sudo apt update 2>&1 | grep -i error

# 2. Restore from backup
sudo cp /etc/apt/sources.list.backup /etc/apt/sources.list

# 3. Clear package cache
sudo apt clean

# 4. Update again
sudo apt update

# 5. If still broken, reset to minimal baseline
echo "deb http://archive.ubuntu.com/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list
sudo apt update
```

---

## Testing New Repositories Safely

Before adding a new repository:

1. **Research the source**
   - Is it official?
   - Is it maintained?
   - Do others trust it?

2. **Add temporarily**
   ```bash
   # Add to sources.list.d with clear name
   echo "deb [signed-by=/path/to/key] https://repo.example.com jammy main" | 
     sudo tee /etc/apt/sources.list.d/test-repo.list
   ```

3. **Test installation**
   ```bash
   sudo apt update
   sudo apt install package-name
   # Test the package
   ```

4. **Remove if problematic**
   ```bash
   sudo rm /etc/apt/sources.list.d/test-repo.list
   sudo apt update
   ```

---

## Automated Monitoring

Create a cron job to alert on repository changes:

```bash
#!/bin/bash
# /usr/local/bin/check-repos.sh

BASELINE="/root/sources.list.baseline"
CURRENT="/etc/apt/sources.list"

if ! diff -q "$BASELINE" "$CURRENT" > /dev/null; then
    echo "WARNING: sources.list has changed!" | mail -s "Repository Alert" admin@example.com
fi
```

---

## Additional Resources

- Ubuntu Security: https://ubuntu.com/security
- Linux Mint Documentation: https://linuxmint.com/documentation.php
- Debian Repository Format: https://wiki.debian.org/SourcesList
- APT Security: https://wiki.debian.org/SecureApt
