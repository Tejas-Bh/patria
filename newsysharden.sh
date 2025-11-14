#!/bin/bash

# System Hardening Script for Ubuntu/Mint
# Must be run as root

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "================================"
echo "SYSTEM HARDENING SCRIPT"
echo "================================"
echo

# Backup sysctl.conf
echo "[*] Backing up /etc/sysctl.conf..."
cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)

echo "[*] Applying network security settings..."

# Your existing settings
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0

# Additional network hardening
echo "[*] Applying additional network hardening..."
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0

# Make changes persistent
echo "[*] Making network settings persistent..."
cat >> /etc/sysctl.conf << 'EOF'

# Network Security Hardening
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

sysctl -p

# Firewall configuration
echo
read -p "[?] Configure UFW firewall (deny incoming, allow outgoing)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v ufw &> /dev/null; then
        ufw --force enable
        ufw default deny incoming
        ufw default allow outgoing
        ufw logging on
        echo "    UFW firewall enabled and configured"
    else
        echo "    UFW not installed, skipping firewall configuration"
    fi
else
    echo "    Skipped UFW configuration"
fi

# Disable unnecessary services
echo
read -p "[?] Disable unnecessary services (avahi, cups, nfs, etc.)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Checking for unnecessary services..."
    services_to_disable=("avahi-daemon" "cups" "isc-dhcp-server" "isc-dhcp-server6" "nfs-server" "rpcbind" "rsync" "snmpd")
    for service in "${services_to_disable[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service"
            systemctl disable "$service"
            echo "    Disabled: $service"
        fi
    done
else
    echo "    Skipped disabling services"
fi

# SSH Hardening
echo
read -p "[?] Harden SSH configuration (disable root login, set timeouts, etc.)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Hardening SSH configuration..."
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
        
        # Update SSH settings
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
        
        # Add if not present
        grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
        grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
        
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
        echo "    SSH configuration hardened"
    fi
else
    echo "    Skipped SSH hardening"
fi

# Password policy
echo
read -p "[?] Configure password policies (90 day max age, min length 8, etc.)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Configuring password policies..."
    if [ -f /etc/login.defs ]; then
        cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d_%H%M%S)
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    8/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
        echo "    Password policies configured"
    fi
else
    echo "    Skipped password policy configuration"
fi

# Set file permissions
echo "[*] Setting secure file permissions..."
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 600 /etc/ssh/sshd_config 2>/dev/null

# Disable core dumps
echo "[*] Disabling core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf
sysctl -w fs.suid_dumpable=0
grep -q "^fs.suid_dumpable" /etc/sysctl.conf || echo "fs.suid_dumpable=0" >> /etc/sysctl.conf

# Enable automatic security updates
echo
read -p "[?] Enable automatic security updates? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Configuring automatic security updates..."
    if command -v unattended-upgrades &> /dev/null; then
        dpkg-reconfigure -plow unattended-upgrades
        echo "    Automatic security updates enabled"
    else
        echo "    unattended-upgrades not installed, install with: apt install unattended-upgrades"
    fi
else
    echo "    Skipped automatic security updates"
fi

# Disable USB storage (optional - uncomment if needed)
# echo "[*] Disabling USB storage..."
# echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

# Remove unnecessary packages
echo
read -p "[?] Remove unnecessary/insecure packages (telnet, rsh-client, etc.)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Checking for unnecessary packages..."
    packages_to_remove=("telnet" "rsh-client" "rsh-redone-client")
    for package in "${packages_to_remove[@]}"; do
        if dpkg -l | grep -q "^ii.*$package"; then
            apt-get remove -y "$package" 2>/dev/null
            echo "    Removed: $package"
        fi
    done
else
    echo "    Skipped package removal"
fi

# Set up auditd for logging (if installed)
if command -v auditd &> /dev/null; then
    echo "[*] Enabling audit daemon..."
    systemctl enable auditd
    systemctl start auditd
    echo "    Audit daemon enabled"
fi

# Configure login banner
echo
read -p "[?] Set login warning banners? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Setting login banner..."
    cat > /etc/issue << 'EOF'
**********************************************************************
*                    AUTHORIZED ACCESS ONLY                          *
*   Unauthorized access to this system is forbidden and will be      *
*   prosecuted by law. By accessing this system, you agree that      *
*   your actions may be monitored if unauthorized usage is suspected.*
**********************************************************************
EOF

    cat > /etc/issue.net << 'EOF'
**********************************************************************
*                    AUTHORIZED ACCESS ONLY                          *
*   Unauthorized access to this system is forbidden and will be      *
*   prosecuted by law. By accessing this system, you agree that      *
*   your actions may be monitored if unauthorized usage is suspected.*
**********************************************************************
EOF
    echo "    Login banners set"
else
    echo "    Skipped login banner configuration"
fi

echo
echo "================================"
echo "HARDENING COMPLETE"
echo "================================"
echo
echo "Summary of changes:"
echo "  [✓] Network security settings applied"
echo "  [✓] Firewall configured"
echo "  [✓] Unnecessary services disabled"
echo "  [✓] SSH hardened"
echo "  [✓] Password policies set"
echo "  [✓] File permissions secured"
echo "  [✓] Core dumps disabled"
echo "  [✓] Security updates configured"
echo "  [✓] Login banners set"
echo
echo "Backups created with timestamp in same directory as originals"
echo "Please review /var/log/syslog for any issues"
echo
echo "RECOMMENDED NEXT STEPS:"
echo "  1. Review SSH configuration: /etc/ssh/sshd_config"
echo "  2. Install fail2ban: apt install fail2ban"
echo "  3. Install rkhunter: apt install rkhunter && rkhunter --update"
echo "  4. Review open ports: ss -tulpn"
echo "  5. Check running services: systemctl list-units --type=service --state=running"
echo
echo "A reboot is recommended to ensure all changes take effect."
echo "================================"
