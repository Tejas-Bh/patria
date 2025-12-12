#!/bin/bash

# Security Log Analyzer for Ubuntu/Mint
# Can be run as regular user, but root gives more access

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

REPORT_FILE="log_analysis_$(date +%Y%m%d_%H%M%S).txt"

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
log "  SECURITY LOG ANALYSIS"
log "  Started: $(date)"
log "========================================"
log ""

# 1. SSH AUTHENTICATION ANALYSIS
log "${BLUE}[1] SSH AUTHENTICATION ANALYSIS${NC}"
log "----------------------------------------"

AUTH_LOG="/var/log/auth.log"
if [ ! -r "$AUTH_LOG" ]; then
    AUTH_LOG="/var/log/secure"
fi

if [ -r "$AUTH_LOG" ]; then
    log_info "Analyzing SSH authentication attempts..."
    
    # Failed SSH attempts
    failed_ssh=$(grep "Failed password" "$AUTH_LOG" 2>/dev/null | wc -l)
    log "  Total failed SSH password attempts: $failed_ssh"
    
    if [ $failed_ssh -gt 100 ]; then
        log_warning "HIGH number of failed SSH attempts detected!"
    fi
    
    # Top failed SSH users
    log ""
    log_info "Top 10 usernames with failed SSH attempts:"
    grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++){if($i=="for"){print $(i+1)}}}' | \
        sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
    
    # Top attacking IPs
    log ""
    log_info "Top 10 IPs with failed SSH attempts:"
    grep "Failed password" "$AUTH_LOG" 2>/dev/null | \
        awk '{print $(NF-2)}' | sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
    
    # Successful SSH logins
    log ""
    log_info "Recent successful SSH logins:"
    grep "Accepted password\|Accepted publickey" "$AUTH_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    # Root login attempts
    log ""
    root_attempts=$(grep "Failed password for root" "$AUTH_LOG" 2>/dev/null | wc -l)
    if [ $root_attempts -gt 0 ]; then
        log_critical "ROOT LOGIN ATTEMPTS DETECTED: $root_attempts attempts"
        log_info "IPs attempting root login:"
        grep "Failed password for root" "$AUTH_LOG" 2>/dev/null | \
            awk '{print $(NF-2)}' | sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
    else
        log "  No root login attempts detected"
    fi
    
    # SSH logins from unusual times (e.g., 2-6 AM)
    log ""
    log_info "SSH logins during unusual hours (2:00-6:00 AM):"
    grep "Accepted" "$AUTH_LOG" 2>/dev/null | \
        awk '$3 ~ /^0[2-6]:/ {print}' | tail -20 | tee -a "$REPORT_FILE"
    
else
    log_warning "Cannot read auth log (need sudo for full analysis)"
fi

log ""

# 2. SUDO USAGE ANALYSIS
log "${BLUE}[2] SUDO USAGE ANALYSIS${NC}"
log "----------------------------------------"

if [ -r "$AUTH_LOG" ]; then
    log_info "Recent sudo commands executed:"
    grep "sudo.*COMMAND" "$AUTH_LOG" 2>/dev/null | tail -30 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Failed sudo attempts:"
    failed_sudo=$(grep "sudo.*authentication failure" "$AUTH_LOG" 2>/dev/null)
    if [ -n "$failed_sudo" ]; then
        log_warning "Failed sudo attempts detected:"
        echo "$failed_sudo" | tail -20 | tee -a "$REPORT_FILE"
    else
        log "  No failed sudo attempts"
    fi
    
    log ""
    log_info "Users who used sudo (last 24 hours):"
    grep "sudo.*COMMAND" "$AUTH_LOG" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++){if($i=="USER=root"){for(j=1;j<=NF;j++){if($j=="PWD="){print $(j-2); break}}}}}' | \
        cut -d':' -f1 | sort | uniq -c | sort -rn | tee -a "$REPORT_FILE"
else
    log_warning "Cannot read auth log"
fi

log ""

# 3. USER ACCOUNT CHANGES
log "${BLUE}[3] USER ACCOUNT CHANGES${NC}"
log "----------------------------------------"

if [ -r "$AUTH_LOG" ]; then
    log_info "User account additions:"
    added_users=$(grep "useradd\|adduser" "$AUTH_LOG" 2>/dev/null | tail -10)
    if [ -n "$added_users" ]; then
        echo "$added_users" | tee -a "$REPORT_FILE"
    else
        log "  No recent user additions"
    fi
    
    log ""
    log_info "User account deletions:"
    deleted_users=$(grep "userdel" "$AUTH_LOG" 2>/dev/null | tail -10)
    if [ -n "$deleted_users" ]; then
        echo "$deleted_users" | tee -a "$REPORT_FILE"
    else
        log "  No recent user deletions"
    fi
    
    log ""
    log_info "Password changes:"
    passwd_changes=$(grep "password changed" "$AUTH_LOG" 2>/dev/null | tail -10)
    if [ -n "$passwd_changes" ]; then
        echo "$passwd_changes" | tee -a "$REPORT_FILE"
    else
        log "  No recent password changes"
    fi
    
    log ""
    log_info "Group modifications:"
    group_changes=$(grep "group.*add\|group.*del\|groupmod" "$AUTH_LOG" 2>/dev/null | tail -10)
    if [ -n "$group_changes" ]; then
        echo "$group_changes" | tee -a "$REPORT_FILE"
    else
        log "  No recent group modifications"
    fi
fi

log ""

# 4. SYSTEM LOG ANALYSIS
log "${BLUE}[4] SYSTEM LOG ANALYSIS${NC}"
log "----------------------------------------"

SYSLOG="/var/log/syslog"
if [ -r "$SYSLOG" ]; then
    log_info "Recent errors and warnings:"
    grep -E "error|warning|fail|critical" "$SYSLOG" 2>/dev/null | tail -30 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Kernel errors:"
    grep "kernel.*error" "$SYSLOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Segmentation faults (possible exploits):"
    segfaults=$(grep "segfault" "$SYSLOG" 2>/dev/null | tail -10)
    if [ -n "$segfaults" ]; then
        log_warning "Segfaults detected:"
        echo "$segfaults" | tee -a "$REPORT_FILE"
    else
        log "  No recent segfaults"
    fi
else
    log_warning "Cannot read syslog"
fi

log ""

# 5. CRON JOB EXECUTION
log "${BLUE}[5] CRON JOB EXECUTION${NC}"
log "----------------------------------------"

if [ -r "$SYSLOG" ]; then
    log_info "Recent cron job executions:"
    grep "CRON" "$SYSLOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Cron jobs run as root:"
    grep "CRON.*root" "$SYSLOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
fi

log ""

# 6. PACKAGE INSTALLATION/REMOVAL
log "${BLUE}[6] PACKAGE CHANGES${NC}"
log "----------------------------------------"

DPKG_LOG="/var/log/dpkg.log"
if [ -r "$DPKG_LOG" ]; then
    log_info "Recently installed packages:"
    grep "install " "$DPKG_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Recently removed packages:"
    grep "remove " "$DPKG_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Recently upgraded packages:"
    grep "upgrade " "$DPKG_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
else
    log_warning "Cannot read dpkg log"
fi

log ""

# 7. APACHE/NGINX WEB SERVER LOGS (if present)
log "${BLUE}[7] WEB SERVER ACCESS LOGS${NC}"
log "----------------------------------------"

# Check Apache logs
APACHE_ACCESS="/var/log/apache2/access.log"
if [ -r "$APACHE_ACCESS" ]; then
    log_info "Analyzing Apache access logs..."
    
    # Suspicious request patterns
    log_info "Potential SQL injection attempts:"
    grep -iE "union.*select|concat.*\(|' or '1'='1" "$APACHE_ACCESS" 2>/dev/null | tail -10 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Potential XSS attempts:"
    grep -iE "<script|javascript:|onerror=" "$APACHE_ACCESS" 2>/dev/null | tail -10 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Potential path traversal attempts:"
    grep -E "\.\./|%2e%2e" "$APACHE_ACCESS" 2>/dev/null | tail -10 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Top 10 requesting IPs:"
    awk '{print $1}' "$APACHE_ACCESS" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Top 10 user agents:"
    awk -F'"' '{print $6}' "$APACHE_ACCESS" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
fi

# Check Nginx logs
NGINX_ACCESS="/var/log/nginx/access.log"
if [ -r "$NGINX_ACCESS" ]; then
    log_info "Analyzing Nginx access logs..."
    
    log_info "Top 10 requesting IPs:"
    awk '{print $1}' "$NGINX_ACCESS" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "404 errors (potential scanning):"
    grep " 404 " "$NGINX_ACCESS" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
fi

if [ ! -r "$APACHE_ACCESS" ] && [ ! -r "$NGINX_ACCESS" ]; then
    log "  No web server logs found or accessible"
fi

log ""

# 8. FAIL2BAN LOGS (if installed)
log "${BLUE}[8] FAIL2BAN ACTIVITY${NC}"
log "----------------------------------------"

FAIL2BAN_LOG="/var/log/fail2ban.log"
if [ -r "$FAIL2BAN_LOG" ]; then
    log_info "Recent fail2ban bans:"
    grep "Ban " "$FAIL2BAN_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Recent fail2ban unbans:"
    grep "Unban " "$FAIL2BAN_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
else
    log "  fail2ban not installed or log not accessible"
fi

log ""

# 9. KERNEL MESSAGES
log "${BLUE}[9] KERNEL MESSAGES${NC}"
log "----------------------------------------"

KERN_LOG="/var/log/kern.log"
if [ -r "$KERN_LOG" ]; then
    log_info "Recent kernel errors:"
    grep -i "error" "$KERN_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
    
    log ""
    log_info "Out of memory events:"
    oom=$(grep -i "out of memory\|OOM" "$KERN_LOG" 2>/dev/null | tail -10)
    if [ -n "$oom" ]; then
        log_warning "OOM events detected:"
        echo "$oom" | tee -a "$REPORT_FILE"
    else
        log "  No OOM events"
    fi
    
    log ""
    log_info "USB device connections:"
    grep "USB" "$KERN_LOG" 2>/dev/null | tail -20 | tee -a "$REPORT_FILE"
else
    log_warning "Cannot read kernel log"
fi

log ""

# 10. SUMMARY STATISTICS
log "${BLUE}[10] SUMMARY STATISTICS${NC}"
log "----------------------------------------"

if [ -r "$AUTH_LOG" ]; then
    total_failed_logins=$(grep "Failed password" "$AUTH_LOG" 2>/dev/null | wc -l)
    total_successful_logins=$(grep "Accepted password\|Accepted publickey" "$AUTH_LOG" 2>/dev/null | wc -l)
    total_sudo=$(grep "sudo.*COMMAND" "$AUTH_LOG" 2>/dev/null | wc -l)
    
    log "  Total failed login attempts: $total_failed_logins"
    log "  Total successful logins: $total_successful_logins"
    log "  Total sudo commands: $total_sudo"
    
    if [ $total_failed_logins -gt 500 ]; then
        log_critical "VERY HIGH number of failed login attempts!"
    elif [ $total_failed_logins -gt 100 ]; then
        log_warning "High number of failed login attempts"
    fi
fi

log ""
log "========================================"
log "  LOG ANALYSIS COMPLETE"
log "  Report saved to: $REPORT_FILE"
log "========================================"
log ""
log "RECOMMENDATIONS:"
log "1. Review any CRITICAL or WARNING items"
log "2. Investigate unusual login times or locations"
log "3. Check for failed authentications from internal IPs"
log "4. Install fail2ban if not already installed"
log "5. Consider setting up centralized logging (rsyslog/syslog-ng)"
log "6. Rotate logs regularly to preserve evidence"
log ""
