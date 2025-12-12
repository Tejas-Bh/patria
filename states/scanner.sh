#!/bin/bash

# Comprehensive Security Scanner for Ubuntu/Mint
# Must be run as root

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPORT_FILE="security_scan_$(date +%Y%m%d_%H%M%S).txt"

# Function to write to both console and report
log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$REPORT_FILE"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$REPORT_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$REPORT_FILE"
}

log_good() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$REPORT_FILE"
}

log ""
log "========================================"
log "  COMPREHENSIVE SECURITY SCAN"
log "  Started: $(date)"
log "========================================"
log ""

# 1. CHECK FOR UNAUTHORIZED USERS
log "${BLUE}[1] CHECKING USER ACCOUNTS${NC}"
log "----------------------------------------"

# Check for UID 0 users (should only be root)
log_info "Checking for UID 0 accounts (root privileges)..."
uid_zero=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
if [ "$(echo "$uid_zero" | wc -l)" -gt 1 ] || [ "$uid_zero" != "root" ]; then
    log_critical "Multiple UID 0 accounts found: $uid_zero"
else
    log_good "Only root has UID 0"
fi

# Check for users without passwords
log_info "Checking for accounts without passwords..."
no_password=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null)
if [ -n "$no_password" ]; then
    log_warning "Accounts without passwords: $no_password"
else
    log_good "All accounts have passwords set"
fi

# Check for users with login shells
log_info "Non-system users with login shells:"
awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print "  " $1 " (UID: " $3 ")"}' /etc/passwd | tee -a "$REPORT_FILE"

log ""

# 2. CHECK SUID/SGID BINARIES
log "${BLUE}[2] CHECKING SUID/SGID BINARIES${NC}"
log "----------------------------------------"

log_info "Finding SUID binaries (can run with owner privileges)..."
suid_files=$(find / -perm -4000 -type f 2>/dev/null | head -20)
suid_count=$(echo "$suid_files" | wc -l)
log_warning "Found $suid_count SUID binaries (showing first 20):"
echo "$suid_files" | while read file; do
    log "  $file"
done

log ""
log_info "Finding SGID binaries (can run with group privileges)..."
sgid_files=$(find / -perm -2000 -type f 2>/dev/null | head -20)
sgid_count=$(echo "$sgid_files" | wc -l)
log_warning "Found $sgid_count SGID binaries (showing first 20):"
echo "$sgid_files" | while read file; do
    log "  $file"
done

log ""

# 3. CHECK WORLD-WRITABLE FILES
log "${BLUE}[3] CHECKING DANGEROUS FILE PERMISSIONS${NC}"
log "----------------------------------------"

log_info "Searching for world-writable files (excluding /proc, /sys)..."
world_writable=$(find / -path /proc -prune -o -path /sys -prune -o -perm -002 -type f -print 2>/dev/null | head -20)
if [ -n "$world_writable" ]; then
    log_warning "World-writable files found (showing first 20):"
    echo "$world_writable" | while read file; do
        log "  $file"
    done
else
    log_good "No world-writable files found"
fi

log ""
log_info "Checking for files with no owner..."
noowner_files=$(find / -path /proc -prune -o -path /sys -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -20)
if [ -n "$noowner_files" ]; then
    log_warning "Files with no owner found (showing first 20):"
    echo "$noowner_files" | while read file; do
        log "  $file"
    done
else
    log_good "All files have proper ownership"
fi

log ""

# 4. CHECK CRITICAL FILE PERMISSIONS
log "${BLUE}[4] CHECKING CRITICAL FILE PERMISSIONS${NC}"
log "----------------------------------------"

check_file_perms() {
    file=$1
    expected=$2
    actual=$(stat -c %a "$file" 2>/dev/null)
    if [ "$actual" != "$expected" ]; then
        log_warning "$file has permissions $actual (expected $expected)"
    else
        log_good "$file has correct permissions ($actual)"
    fi
}

check_file_perms "/etc/passwd" "644"
check_file_perms "/etc/shadow" "640"
check_file_perms "/etc/group" "644"
check_file_perms "/etc/gshadow" "640"

log ""

# 5. CHECK LISTENING SERVICES AND PORTS
log "${BLUE}[5] CHECKING NETWORK SERVICES${NC}"
log "----------------------------------------"

log_info "Listening ports and services:"
ss -tulpn | grep LISTEN | tee -a "$REPORT_FILE"

log ""
log_info "Established network connections:"
ss -antp | grep ESTAB | head -20 | tee -a "$REPORT_FILE"

log ""

# 6. CHECK RUNNING SERVICES
log "${BLUE}[6] CHECKING RUNNING SERVICES${NC}"
log "----------------------------------------"

log_info "Active services:"
systemctl list-units --type=service --state=running --no-pager | tee -a "$REPORT_FILE"

log ""

# 7. CHECK FOR SUSPICIOUS PROCESSES
log "${BLUE}[7] CHECKING FOR SUSPICIOUS PROCESSES${NC}"
log "----------------------------------------"

log_info "Processes running from temporary directories:"
suspicious_procs=$(ps aux | grep -E '/tmp/|/var/tmp/|/dev/shm/' | grep -v grep)
if [ -n "$suspicious_procs" ]; then
    log_warning "Suspicious processes found:"
    echo "$suspicious_procs" | tee -a "$REPORT_FILE"
else
    log_good "No processes running from temp directories"
fi

log ""
log_info "Checking for hidden processes (comparing ps and /proc)..."
ps_count=$(ps aux | wc -l)
proc_count=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
if [ $((proc_count - ps_count)) -gt 5 ]; then
    log_warning "Possible hidden processes detected (ps: $ps_count, /proc: $proc_count)"
else
    log_good "Process counts match (ps: $ps_count, /proc: $proc_count)"
fi

log ""

# 8. CHECK CRON JOBS
log "${BLUE}[8] CHECKING SCHEDULED TASKS (CRON)${NC}"
log "----------------------------------------"

log_info "System cron jobs:"
ls -la /etc/cron.* 2>/dev/null | tee -a "$REPORT_FILE"

log ""
log_info "User cron jobs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null && log "Cron for $user:" && crontab -u "$user" -l 2>/dev/null | tee -a "$REPORT_FILE"
done

log ""

# 9. CHECK SSH CONFIGURATION
log "${BLUE}[9] CHECKING SSH SECURITY${NC}"
log "----------------------------------------"

if [ -f /etc/ssh/sshd_config ]; then
    log_info "Checking SSH configuration..."
    
    permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$permit_root" = "yes" ]; then
        log_critical "Root login via SSH is ENABLED"
    else
        log_good "Root login via SSH is disabled"
    fi
    
    permit_empty=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$permit_empty" = "yes" ]; then
        log_critical "Empty passwords are ALLOWED"
    else
        log_good "Empty passwords are disabled"
    fi
    
    log_info "Checking for unauthorized SSH keys..."
    for homedir in /home/*; do
        if [ -f "$homedir/.ssh/authorized_keys" ]; then
            username=$(basename "$homedir")
            log "  $username has authorized_keys:"
            cat "$homedir/.ssh/authorized_keys" | tee -a "$REPORT_FILE"
        fi
    done
fi

log ""

# 10. CHECK FOR SUSPICIOUS FILES IN TEMP DIRECTORIES
log "${BLUE}[10] CHECKING TEMPORARY DIRECTORIES${NC}"
log "----------------------------------------"

check_temp_dir() {
    dir=$1
    log_info "Checking $dir..."
    suspicious=$(find "$dir" -type f -name ".*" -o -name "*.sh" -o -name "*.py" 2>/dev/null | head -10)
    if [ -n "$suspicious" ]; then
        log_warning "Suspicious files in $dir:"
        echo "$suspicious" | while read file; do
            log "  $file ($(stat -c %y "$file"))"
        done
    else
        log_good "No suspicious files in $dir"
    fi
}

check_temp_dir "/tmp"
check_temp_dir "/var/tmp"
check_temp_dir "/dev/shm"

log ""

# 11. CHECK BASH HISTORY FOR SUSPICIOUS COMMANDS
log "${BLUE}[11] CHECKING BASH HISTORY${NC}"
log "----------------------------------------"

log_info "Searching for suspicious commands in bash history..."
suspicious_patterns="nc|netcat|/dev/tcp|base64|wget.*http|curl.*http|chmod 777|rm -rf /"

for homedir in /home/* /root; do
    if [ -f "$homedir/.bash_history" ]; then
        username=$(basename "$homedir")
        suspicious_cmds=$(grep -E "$suspicious_patterns" "$homedir/.bash_history" 2>/dev/null | tail -5)
        if [ -n "$suspicious_cmds" ]; then
            log_warning "Suspicious commands in $username's history:"
            echo "$suspicious_cmds" | while read cmd; do
                log "  $cmd"
            done
        fi
    fi
done

log ""

# 12. CHECK LOADED KERNEL MODULES
log "${BLUE}[12] CHECKING KERNEL MODULES${NC}"
log "----------------------------------------"

log_info "Currently loaded kernel modules:"
lsmod | head -20 | tee -a "$REPORT_FILE"

log ""

# 13. CHECK FIREWALL STATUS
log "${BLUE}[13] CHECKING FIREWALL${NC}"
log "----------------------------------------"

if command -v ufw &> /dev/null; then
    ufw_status=$(ufw status)
    if echo "$ufw_status" | grep -q "Status: active"; then
        log_good "UFW firewall is active"
        echo "$ufw_status" | tee -a "$REPORT_FILE"
    else
        log_warning "UFW firewall is INACTIVE"
    fi
else
    log_warning "UFW not installed"
fi

log ""

# 14. CHECK RECENT LOGINS
log "${BLUE}[14] CHECKING LOGIN HISTORY${NC}"
log "----------------------------------------"

log_info "Last 20 successful logins:"
last -20 | tee -a "$REPORT_FILE"

log ""
log_info "Last 20 failed login attempts:"
lastb -20 2>/dev/null | tee -a "$REPORT_FILE" || log "No failed login records (or insufficient permissions)"

log ""

# 15. CHECK PACKAGE INTEGRITY
log "${BLUE}[15] CHECKING PACKAGE INTEGRITY${NC}"
log "----------------------------------------"

if command -v debsums &> /dev/null; then
    log_info "Checking package file integrity (this may take a while)..."
    modified_files=$(debsums -c 2>/dev/null | head -20)
    if [ -n "$modified_files" ]; then
        log_warning "Modified package files detected (showing first 20):"
        echo "$modified_files" | tee -a "$REPORT_FILE"
    else
        log_good "All package files have correct checksums"
    fi
else
    log_warning "debsums not installed (install with: apt install debsums)"
fi

log ""

# SUMMARY
log "========================================"
log "  SCAN COMPLETE"
log "  Report saved to: $REPORT_FILE"
log "========================================"
log ""
log "RECOMMENDATIONS:"
log "1. Review any CRITICAL or WARNING items above"
log "2. Install additional security tools:"
log "   - rkhunter (rootkit detection)"
log "   - chkrootkit (rootkit detection)"
log "   - lynis (security auditing)"
log "   - fail2ban (brute force protection)"
log "   - aide (file integrity monitoring)"
log "3. Review logs regularly in /var/log/"
log "4. Keep system updated: apt update && apt upgrade"
log ""
