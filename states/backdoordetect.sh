#!/bin/bash

# Backdoor Detection Script for Ubuntu/Mint
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

REPORT_FILE="backdoor_scan_$(date +%Y%m%d_%H%M%S).txt"

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$REPORT_FILE"
}

log_critical() {
    echo -e "${RED}[!!!]${NC} $1" | tee -a "$REPORT_FILE"
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$REPORT_FILE"
}

log ""
log "========================================"
log "  BACKDOOR DETECTION SCAN"
log "  Started: $(date)"
log "========================================"
log ""

# 1. CHECK FOR REVERSE SHELLS
log "${BLUE}[1] CHECKING FOR REVERSE SHELLS${NC}"
log "----------------------------------------"

log_info "Searching for netcat/bash reverse shell patterns..."
reverse_shell_procs=$(ps aux | grep -E 'nc.*-e|/bin/bash.*-i|/bin/sh.*-i|perl.*socket|python.*socket' | grep -v grep)
if [ -n "$reverse_shell_procs" ]; then
    log_critical "POTENTIAL REVERSE SHELL DETECTED:"
    echo "$reverse_shell_procs" | tee -a "$REPORT_FILE"
else
    log "  No obvious reverse shells detected in processes"
fi

log ""
log_info "Checking for suspicious /dev/tcp connections in bash history..."
for homedir in /home/* /root; do
    if [ -f "$homedir/.bash_history" ]; then
        dev_tcp=$(grep -E '/dev/tcp/|/dev/udp/' "$homedir/.bash_history" 2>/dev/null)
        if [ -n "$dev_tcp" ]; then
            log_warning "Suspicious network connections in $(basename $homedir)/.bash_history:"
            echo "$dev_tcp" | tee -a "$REPORT_FILE"
        fi
    fi
done

log ""

# 2. CHECK FOR BACKDOOR USERS
log "${BLUE}[2] CHECKING FOR BACKDOOR USER ACCOUNTS${NC}"
log "----------------------------------------"

log_info "Checking for hidden users (UID 0 but not root)..."
hidden_root=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -n "$hidden_root" ]; then
    log_critical "HIDDEN ROOT USERS FOUND: $hidden_root"
else
    log "  No hidden root users found"
fi

log ""
log_info "Checking for users with suspicious names..."
suspicious_users=$(awk -F: '$1 ~ /^\./ || $1 ~ /[[:space:]]/ || $1 ~ /^[0-9]+$/ {print $1}' /etc/passwd)
if [ -n "$suspicious_users" ]; then
    log_warning "Suspicious usernames found: $suspicious_users"
else
    log "  No suspicious usernames found"
fi

log ""
log_info "Checking for recently created users (last 30 days)..."
recent_users=$(find /home -maxdepth 1 -type d -mtime -30 2>/dev/null | grep -v "^/home$")
if [ -n "$recent_users" ]; then
    log_warning "Recently created home directories:"
    echo "$recent_users" | tee -a "$REPORT_FILE"
fi

log ""

# 3. CHECK SSH KEYS
log "${BLUE}[3] CHECKING SSH KEYS${NC}"
log "----------------------------------------"

log_info "Scanning authorized_keys for all users..."
for homedir in /home/* /root; do
    authkeys="$homedir/.ssh/authorized_keys"
    if [ -f "$authkeys" ]; then
        username=$(basename "$homedir")
        log "  User: $username"
        
        # Check for suspicious key comments or patterns
        suspicious_keys=$(grep -E 'backdoor|shell|pwn|hack|@[0-9]' "$authkeys" 2>/dev/null)
        if [ -n "$suspicious_keys" ]; then
            log_critical "SUSPICIOUS SSH KEY FOUND for $username:"
            echo "$suspicious_keys" | tee -a "$REPORT_FILE"
        fi
        
        # List all keys with their fingerprints
        while read -r key; do
            if [ -n "$key" ]; then
                fingerprint=$(echo "$key" | ssh-keygen -lf - 2>/dev/null)
                log "    $fingerprint"
            fi
        done < "$authkeys"
        log ""
    fi
done

# Check for SSH keys in unusual locations
log_info "Checking for SSH keys in unusual locations..."
unusual_keys=$(find / -name "authorized_keys" 2>/dev/null | grep -v "/.ssh/authorized_keys")
if [ -n "$unusual_keys" ]; then
    log_warning "SSH keys found in unusual locations:"
    echo "$unusual_keys" | tee -a "$REPORT_FILE"
fi

log ""

# 4. CHECK FOR WEBSHELLS
log "${BLUE}[4] CHECKING FOR WEBSHELLS${NC}"
log "----------------------------------------"

web_dirs="/var/www /usr/share/nginx /opt/lampp/htdocs"
log_info "Scanning web directories for potential webshells..."

for dir in $web_dirs; do
    if [ -d "$dir" ]; then
        log "  Scanning $dir..."
        
        # Common webshell patterns
        webshells=$(find "$dir" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \) \
            -exec grep -l -E 'eval\(|base64_decode|exec\(|system\(|passthru\(|shell_exec|assert\(|preg_replace.*\/e' {} \; 2>/dev/null)
        
        if [ -n "$webshells" ]; then
            log_warning "Potential webshells detected:"
            echo "$webshells" | while read file; do
                log "    $file"
            done
        fi
        
        # Check for suspicious filenames
        suspicious_files=$(find "$dir" -type f -name "*.php" \
            -exec grep -l "c99\|r57\|b374k\|wso\|shell\|c100\|r00t" {} \; 2>/dev/null)
        if [ -n "$suspicious_files" ]; then
            log_warning "Files with suspicious names:"
            echo "$suspicious_files" | tee -a "$REPORT_FILE"
        fi
    fi
done

log ""

# 5. CHECK FOR ROOTKIT INDICATORS
log "${BLUE}[5] CHECKING FOR ROOTKIT INDICATORS${NC}"
log "----------------------------------------"

log_info "Checking for common rootkit files..."
rootkit_files=(
    "/dev/shm/.ice-unix"
    "/usr/include/..  "
    "/usr/lib/.wormie"
    "/usr/lib/.wmrc"
    "/usr/share/.bash_history"
    "/var/local/.lpd"
    "/var/run/.tmp"
    "/tmp/.1991"
)

for file in "${rootkit_files[@]}"; do
    if [ -e "$file" ]; then
        log_critical "ROOTKIT FILE DETECTED: $file"
    fi
done

log ""
log_info "Checking for LKM (Loadable Kernel Module) rootkits..."
suspicious_modules=$(lsmod | grep -E 'diamorphine|reptile|suterusu|rootkit')
if [ -n "$suspicious_modules" ]; then
    log_critical "SUSPICIOUS KERNEL MODULE DETECTED:"
    echo "$suspicious_modules" | tee -a "$REPORT_FILE"
else
    log "  No known rootkit modules detected"
fi

log ""

# 6. CHECK SYSTEM BINARIES
log "${BLUE}[6] CHECKING SYSTEM BINARY INTEGRITY${NC}"
log "----------------------------------------"

log_info "Checking critical system binaries for modifications..."
critical_bins="/bin/ls /bin/ps /bin/netstat /usr/bin/find /usr/bin/lsof /usr/bin/top"

if command -v debsums &> /dev/null; then
    for bin in $critical_bins; do
        if [ -f "$bin" ]; then
            result=$(debsums -c "$bin" 2>/dev/null)
            if [ -n "$result" ]; then
                log_warning "Modified binary: $bin"
            fi
        fi
    done
else
    log_warning "debsums not installed - cannot verify binary integrity"
    log "  Install with: apt install debsums"
fi

log ""

# 7. CHECK FOR PERSISTENCE MECHANISMS
log "${BLUE}[7] CHECKING PERSISTENCE MECHANISMS${NC}"
log "----------------------------------------"

log_info "Checking startup scripts..."
startup_locations=(
    "/etc/rc.local"
    "/etc/init.d"
    "/etc/systemd/system"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
)

for location in "${startup_locations[@]}"; do
    if [ -e "$location" ]; then
        recent=$(find "$location" -type f -mtime -7 2>/dev/null)
        if [ -n "$recent" ]; then
            log_warning "Recently modified files in $location:"
            echo "$recent" | while read file; do
                log "  $file (modified: $(stat -c %y "$file" | cut -d' ' -f1))"
            done
        fi
    fi
done

log ""
log_info "Checking user profile files for suspicious modifications..."
for homedir in /home/* /root; do
    for file in .bashrc .bash_profile .profile .bash_login; do
        fullpath="$homedir/$file"
        if [ -f "$fullpath" ]; then
            # Check for suspicious patterns
            suspicious=$(grep -E 'nc -l|wget.*\|.*sh|curl.*\|.*sh|base64.*exec|export.*LD_PRELOAD' "$fullpath" 2>/dev/null)
            if [ -n "$suspicious" ]; then
                log_critical "SUSPICIOUS CODE in $fullpath:"
                echo "$suspicious" | tee -a "$REPORT_FILE"
            fi
        fi
    done
done

log ""

# 8. CHECK FOR LISTENING BACKDOORS
log "${BLUE}[8] CHECKING FOR LISTENING BACKDOORS${NC}"
log "----------------------------------------"

log_info "Checking for unusual listening ports..."
listening=$(ss -tulpn | grep LISTEN)

# Common backdoor ports
backdoor_ports="31337 12345 54321 6667 1337 8080 4444 5555"
for port in $backdoor_ports; do
    if echo "$listening" | grep -q ":$port"; then
        log_warning "SUSPICIOUS PORT LISTENING: $port"
        echo "$listening" | grep ":$port" | tee -a "$REPORT_FILE"
    fi
done

log ""
log_info "All listening ports:"
echo "$listening" | tee -a "$REPORT_FILE"

log ""

# 9. CHECK PROCESS HIDING
log "${BLUE}[9] CHECKING FOR PROCESS HIDING${NC}"
log "----------------------------------------"

log_info "Comparing process counts..."
ps_count=$(ps aux | wc -l)
proc_count=$(ls -1 /proc | grep -E '^[0-9]+$' | wc -l)
diff=$((proc_count - ps_count))

if [ $diff -gt 10 ]; then
    log_critical "LARGE DISCREPANCY between ps ($ps_count) and /proc ($proc_count)"
    log "  This may indicate hidden processes (rootkit)"
elif [ $diff -gt 5 ]; then
    log_warning "Minor discrepancy between ps ($ps_count) and /proc ($proc_count)"
else
    log "  Process counts match (ps: $ps_count, /proc: $proc_count)"
fi

log ""

# 10. CHECK SUSPICIOUS NETWORK CONNECTIONS
log "${BLUE}[10] CHECKING SUSPICIOUS NETWORK CONNECTIONS${NC}"
log "----------------------------------------"

log_info "Checking for connections to suspicious IPs..."
connections=$(ss -antp | grep ESTAB)

# Check for connections to Tor, known C2, etc.
if echo "$connections" | grep -qE ':9001|:9030|:9050|:9051'; then
    log_warning "Tor-related connections detected"
    echo "$connections" | grep -E ':9001|:9030|:9050|:9051' | tee -a "$REPORT_FILE"
fi

log ""
log_info "All established connections:"
echo "$connections" | tee -a "$REPORT_FILE"

log ""

# SUMMARY
log "========================================"
log "  BACKDOOR SCAN COMPLETE"
log "  Report saved to: $REPORT_FILE"
log "========================================"
log ""
log "NEXT STEPS:"
log "1. Review all CRITICAL findings immediately"
log "2. Investigate any WARNING items"
log "3. Run rootkit scanners:"
log "   - rkhunter --check"
log "   - chkrootkit"
log "4. Check system logs in /var/log/"
log "5. If compromised, consider:"
log "   - Isolate the system from network"
log "   - Preserve evidence"
log "   - Rebuild from clean media"
log ""
