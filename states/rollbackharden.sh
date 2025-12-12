#!/bin/bash

# Rollback Hardening Script for Ubuntu/Mint
# Reverts changes made by the hardening script
# Must be run as root

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================"
echo "  HARDENING ROLLBACK SCRIPT"
echo "========================================${NC}"
echo ""
echo "This script will revert changes made by the hardening script."
echo "It will restore from backup files created during hardening."
echo ""
echo -e "${YELLOW}WARNING: This will undo security hardening!${NC}"
echo ""
read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Rollback cancelled."
    exit 0
fi

echo ""

# Function to find and restore most recent backup
restore_backup() {
    original=$1
    description=$2
    
    # Find the most recent backup
    backup=$(ls -t ${original}.backup.* 2>/dev/null | head -1)
    
    if [ -f "$backup" ]; then
        echo -e "${BLUE}[*]${NC} Restoring $description..."
        echo "    From: $backup"
        echo "    To: $original"
        
        # Create a backup of current file before restoring
        cp "$original" "${original}.before_rollback.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        
        # Restore the backup
        cp "$backup" "$original"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}    ✓ Restored successfully${NC}"
            return 0
        else
            echo -e "${RED}    ✗ Failed to restore${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}[!]${NC} No backup found for $description ($original)"
        return 1
    fi
}

# Function to list available backups
list_backups() {
    file=$1
    description=$2
    
    backups=$(ls -t ${file}.backup.* 2>/dev/null)
    
    if [ -n "$backups" ]; then
        echo -e "${BLUE}Available backups for $description:${NC}"
        echo "$backups" | while read backup; do
            timestamp=$(echo "$backup" | grep -oP '\d{8}_\d{6}')
            date_formatted=$(date -d "${timestamp:0:8} ${timestamp:9:2}:${timestamp:11:2}:${timestamp:13:2}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
            echo "  - $backup ($date_formatted)"
        done
        echo ""
    fi
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}[1] LISTING AVAILABLE BACKUPS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

list_backups "/etc/sysctl.conf" "sysctl configuration"
list_backups "/etc/ssh/sshd_config" "SSH configuration"
list_backups "/etc/login.defs" "login definitions"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}[2] RESTORING FROM BACKUPS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

restored_count=0
failed_count=0

# Restore sysctl.conf
if restore_backup "/etc/sysctl.conf" "sysctl configuration"; then
    restored_count=$((restored_count + 1))
    
    # Remove the hardening entries we added
    echo -e "${BLUE}[*]${NC} Removing hardening entries from sysctl.conf..."
    sed -i '/# Network Security Hardening/,/net.ipv6.conf.default.accept_redirects=0/d' /etc/sysctl.conf
    
    # Apply the restored sysctl settings
    echo -e "${BLUE}[*]${NC} Applying restored sysctl settings..."
    sysctl -p
else
    failed_count=$((failed_count + 1))
fi

echo ""

# Restore SSH config
if restore_backup "/etc/ssh/sshd_config" "SSH configuration"; then
    restored_count=$((restored_count + 1))
    
    # Restart SSH service
    echo -e "${BLUE}[*]${NC} Restarting SSH service..."
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}    ✓ SSH service restarted${NC}"
    else
        echo -e "${RED}    ✗ Failed to restart SSH service${NC}"
    fi
else
    failed_count=$((failed_count + 1))
fi

echo ""

# Restore login.defs
if restore_backup "/etc/login.defs" "login definitions"; then
    restored_count=$((restored_count + 1))
else
    failed_count=$((failed_count + 1))
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}[3] REVERTING OTHER CHANGES${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Re-enable UFW if it was disabled
read -p "Do you want to disable UFW firewall? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Disabling UFW firewall..."
    ufw disable
    echo -e "${GREEN}    ✓ UFW disabled${NC}"
fi

echo ""

# Re-enable services
read -p "Do you want to re-enable services that were disabled? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Checking for disabled services..."
    
    services_to_check=("avahi-daemon" "cups" "isc-dhcp-server" "isc-dhcp-server6" "nfs-server" "rpcbind" "rsync" "snmpd")
    
    echo "Which services would you like to re-enable?"
    echo "(You can enable them individually if needed)"
    echo ""
    
    for service in "${services_to_check[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            status=$(systemctl is-enabled "$service" 2>/dev/null)
            if [ "$status" = "disabled" ]; then
                read -p "  Re-enable $service? [y/N]: " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    systemctl enable "$service"
                    systemctl start "$service"
                    echo -e "${GREEN}    ✓ $service enabled and started${NC}"
                fi
            fi
        fi
    done
fi

echo ""

# Remove core dump restriction
read -p "Do you want to re-enable core dumps? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Re-enabling core dumps..."
    
    # Remove the hard limit
    sed -i '/\* hard core 0/d' /etc/security/limits.conf
    
    # Reset sysctl setting
    sysctl -w fs.suid_dumpable=1
    sed -i '/^fs.suid_dumpable=0/d' /etc/sysctl.conf
    
    echo -e "${GREEN}    ✓ Core dumps re-enabled${NC}"
fi

echo ""

# Remove login banners
read -p "Do you want to remove login warning banners? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Removing login banners..."
    
    echo "" > /etc/issue
    echo "" > /etc/issue.net
    
    echo -e "${GREEN}    ✓ Login banners removed${NC}"
fi

echo ""

# Disable unattended upgrades
read -p "Do you want to disable automatic security updates? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Disabling automatic security updates..."
    
    if command -v unattended-upgrades &> /dev/null; then
        echo 'APT::Periodic::Unattended-Upgrade "0";' > /etc/apt/apt.conf.d/20auto-upgrades
        echo -e "${GREEN}    ✓ Automatic updates disabled${NC}"
    else
        echo "    unattended-upgrades not installed"
    fi
fi

echo ""

# Restore file permissions to defaults (careful with this)
read -p "Do you want to restore default file permissions for system files? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[*]${NC} Restoring default file permissions..."
    
    # Note: These are Ubuntu defaults, may vary
    chmod 644 /etc/passwd 2>/dev/null && echo "    /etc/passwd: 644"
    chmod 640 /etc/shadow 2>/dev/null && echo "    /etc/shadow: 640"
    chmod 644 /etc/group 2>/dev/null && echo "    /etc/group: 644"
    chmod 640 /etc/gshadow 2>/dev/null && echo "    /etc/gshadow: 640"
    # Note: We keep secure permissions for these files as they should be secure anyway
    
    echo -e "${GREEN}    ✓ Permissions restored${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}[4] SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Rollback completed:"
echo "  - Restored configurations: $restored_count"
echo "  - Failed restorations: $failed_count"
echo ""

if [ $restored_count -gt 0 ]; then
    echo -e "${GREEN}✓ Rollback successful!${NC}"
    echo ""
    echo "Backup files have been preserved in case you need them."
    echo "Files before rollback are saved with '.before_rollback' suffix."
else
    echo -e "${YELLOW}! No files were restored${NC}"
    echo "This might be because:"
    echo "  - No backups were found"
    echo "  - Hardening script was never run"
    echo "  - Backup files were deleted"
fi

echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - System is now LESS SECURE than it was"
echo "  - Review what changes you've reverted"
echo "  - Consider re-hardening after fixing issues"
echo "  - A reboot is recommended"
echo ""
echo "To view what was changed, compare the backup files:"
echo "  diff /etc/sysctl.conf /etc/sysctl.conf.backup.*"
echo ""
echo -e "${BLUE}========================================${NC}"
