#!/bin/bash

# File Permission Audit Script for Ubuntu/Mint
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

REPORT_FILE="file_permissions_audit_$(date +%Y%m%d_%H%M%S).txt"

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

log_good() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$REPORT_FILE"
}

log ""
log "========================================"
log "  FILE PERMISSION AUDIT"
log "  Started: $(date)"
log "========================================"
log ""
log "NOTE: Large scans may take several minutes..."
log ""

# Function to check file permissions
check_perms() {
    file=$1
    expected=$2
    description=$3
    
    if [ -e "$file" ]; then
        actual=$(stat -c %a "$file" 2>/dev/null)
        if [ "$actual" != "$expected" ]; then
            log_warning "$description: $file"
            log "  Expected: $expected, Actual: $actual"
        else
            log_good "$description: $file ($actual)"
        fi
    else
        log "  File not found: $file"
    fi
}

# 1. CRITICAL SYSTEM FILES
log "${BLUE}[1] CHECKING CRITICAL SYSTEM FILES${NC}"
log "----------------------------------------"

log_info "Checking /etc/passwd..."
check_perms "/etc/passwd" "644" "Password file"

log_info "Checking /etc/shadow..."
check_perms "/etc/shadow" "640" "Shadow password file"
# Also check if it's readable by others
if [ -r /etc/shadow ]; then
    perms=$(stat -c %a /etc/shadow)
    if [ "$perms" = "644" ] || [ "$perms" = "666" ]; then
        log_critical "/etc/shadow is WORLD READABLE! ($perms)"
    fi
fi

log_info "Checking /etc/group..."
check_perms "/etc/group" "644" "Group file"

log_info "Checking /etc/gshadow..."
check_perms "/etc/gshadow" "640" "Shadow group file"

log_info "Checking /boot/grub/grub.cfg..."
check_perms "/boot/grub/grub.cfg" "600" "GRUB config"

log_info "Checking /etc/ssh/sshd_config..."
check_perms "/etc/ssh/sshd_config" "600" "SSH config"

log ""

# 2. SUID/SGID FILES
log "${BLUE}[2] AUDITING SUID/SGID BINARIES${NC}"
log "----------------------------------------"

log_info "Scanning for SUID binaries (this may take a few minutes)..."
suid_files=$(find / -path /proc -prune -o -path /sys -prune -o -perm -4000 -type f -print 2>/dev/null)

# Known safe SUID binaries (common on Ubuntu/Mint)
known_safe=(
    "/usr/bin/sudo"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/su"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
)

suid_count=0
suspicious_count=0

echo "$suid_files" | while read file; do
    if [ -n "$file" ]; then
        suid_count=$((suid_count + 1))
        is_known=0
        
        for safe in "${known_safe[@]}"; do
            if [ "$file" = "$safe" ]; then
                is_known=1
                break
            fi
        done
        
        if [ $is_known -eq 0 ]; then
            log_warning "Unusual SUID binary: $file"
            suspicious_count=$((suspicious_count + 1))
        fi
    fi
done

log ""
log_info "Found $(echo "$suid_files" | wc -l) SUID binaries"
log ""
log_info "Scanning for SGID binaries..."
sgid_files=$(find / -path /proc -prune -o -path /sys -prune -o -perm -2000 -type f -print 2>/dev/null)
log "Found $(echo "$sgid_files" | wc -l) SGID binaries"

log ""

# 3. WORLD-WRITABLE FILES
log "${BLUE}[3] SCANNING FOR WORLD-WRITABLE FILES${NC}"
log "----------------------------------------"

log_info "Searching for world-writable files (excluding /proc, /sys, /tmp, /var/tmp)..."
world_writable=$(find / -path /proc -prune -o -path /sys -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -perm -002 -type f -print 2>/dev/null)

ww_count=$(echo "$world_writable" | grep -c .)
if [ $ww_count -gt 0 ]; then
    log_warning "Found $ww_count world-writable files"
    log "First 20 world-writable files:"
    echo "$world_writable" | head -20 | while read file; do
        log "  $file ($(stat -c %a "$file"))"
    done
else
    log_good "No world-writable files found outside temp directories"
fi

log ""

# 4. WORLD-WRITABLE DIRECTORIES
log "${BLUE}[4] CHECKING WORLD-WRITABLE DIRECTORIES${NC}"
log "----------------------------------------"

log_info "Searching for world-writable directories without sticky bit..."
# Sticky bit prevents users from deleting files they don't own
ww_dirs=$(find / -path /proc -prune -o -path /sys -prune -o -type d -perm -002 ! -perm -1000 -print 2>/dev/null)

wwd_count=$(echo "$ww_dirs" | grep -c .)
if [ $wwd_count -gt 0 ]; then
    log_warning "Found $wwd_count world-writable directories without sticky bit"
    echo "$ww_dirs" | head -20 | while read dir; do
        log "  $dir ($(stat -c %a "$dir"))"
    done
else
    log_good "All world-writable directories have sticky bit set"
fi

log ""

# 5. FILES WITH NO OWNER
log "${BLUE}[5] CHECKING FOR ORPHANED FILES${NC}"
log "----------------------------------------"

log_info "Searching for files with no owner (orphaned files)..."
orphaned=$(find / -path /proc -prune -o -path /sys -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null)

orphan_count=$(echo "$orphaned" | grep -c .)
if [ $orphan_count -gt 0 ]; then
    log_warning "Found $orphan_count orphaned files"
    log "First 20 orphaned files:"
    echo "$orphaned" | head -20 | while read file; do
        owner=$(stat -c "UID:%u GID:%g" "$file")
        log "  $file ($owner)"
    done
else
    log_good "No orphaned files found"
fi

log ""

# 6. HOME DIRECTORY PERMISSIONS
log "${BLUE}[6] AUDITING HOME DIRECTORY PERMISSIONS${NC}"
log "----------------------------------------"

log_info "Checking home directory permissions..."
for homedir in /home/*; do
    if [ -d "$homedir" ]; then
        username=$(basename "$homedir")
        perms=$(stat -c %a "$homedir")
        
        # Home directories should typically be 700 or 750
        if [ "$perms" = "777" ] || [ "$perms" = "775" ] || [ "$perms" = "755" ]; then
            log_warning "Home directory too permissive: $homedir ($perms)"
        elif [[ $perms == *7 ]] || [[ $perms == *6 ]] || [[ $perms == *5 ]]; then
            log_warning "Home directory world-accessible: $homedir ($perms)"
        else
            log "  $homedir: $perms [OK]"
        fi
        
        # Check .ssh directory
        ssh_dir="$homedir/.ssh"
        if [ -d "$ssh_dir" ]; then
            ssh_perms=$(stat -c %a "$ssh_dir")
            if [ "$ssh_perms" != "700" ]; then
                log_warning ".ssh directory permissions: $ssh_dir ($ssh_perms) - should be 700"
            fi
            
            # Check authorized_keys
            authkeys="$ssh_dir/authorized_keys"
            if [ -f "$authkeys" ]; then
                key_perms=$(stat -c %a "$authkeys")
                if [ "$key_perms" != "600" ] && [ "$key_perms" != "644" ]; then
                    log_warning "authorized_keys permissions: $authkeys ($key_perms)"
                fi
            fi
            
            # Check private keys
            for keyfile in "$ssh_dir"/id_*; do
                if [ -f "$keyfile" ] && [[ ! "$keyfile" == *.pub ]]; then
                    key_perms=$(stat -c %a "$keyfile")
                    if [ "$key_perms" != "600" ]; then
                        log_critical "Private key too permissive: $keyfile ($key_perms)"
                    fi
                fi
            done
        fi
    fi
done

log ""

# 7. EXECUTABLE FILES IN SUSPICIOUS LOCATIONS
log "${BLUE}[7] CHECKING EXECUTABLE FILES IN TEMP DIRECTORIES${NC}"
log "----------------------------------------"

check_executables() {
    dir=$1
    log_info "Checking $dir for executable files..."
    execs=$(find "$dir" -type f -executable 2>/dev/null)
    if [ -n "$execs" ]; then
        log_warning "Executable files found in $dir:"
        echo "$execs" | head -10 | while read file; do
            log "  $file"
        done
    else
        log_good "No executable files in $dir"
    fi
}

check_executables "/tmp"
check_executables "/var/tmp"
check_executables "/dev/shm"

log ""

# 8. SETUID/SETGID DIRECTORIES
log "${BLUE}[8] CHECKING FOR SETUID/SETGID DIRECTORIES${NC}"
log "----------------------------------------"

log_info "Searching for directories with setuid/setgid bit..."
setid_dirs=$(find / -path /proc -prune -o -path /sys -prune -o -type d \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)

if [ -n "$setid_dirs" ]; then
    log_warning "Directories with setuid/setgid:"
    echo "$setid_dirs" | while read dir; do
        log "  $dir ($(stat -c %a "$dir"))"
    done
else
    log_good "No directories with setuid/setgid found"
fi

log ""

# 9. DOT FILES IN /
log "${BLUE}[9] CHECKING ROOT DIRECTORY FOR DOT FILES${NC}"
log "----------------------------------------"

log_info "Checking for hidden files in / (possible malware)..."
dot_files=$(find / -maxdepth 1 -name ".*" -type f 2>/dev/null)
if [ -n "$dot_files" ]; then
    log_warning "Hidden files in /:"
    echo "$dot_files" | while read file; do
        log "  $file"
    done
else
    log_good "No unusual hidden files in /"
fi

log ""

# 10. WRITABLE SYSTEM DIRECTORIES
log "${BLUE}[10] CHECKING WRITABLE SYSTEM DIRECTORIES${NC}"
log "----------------------------------------"

log_info "Checking if critical system directories are writable by non-root..."
critical_dirs="/etc /boot /usr/bin /usr/sbin /bin /sbin"

for dir in $critical_dirs; do
    if [ -d "$dir" ]; then
        perms=$(stat -c %a "$dir")
        if [[ $perms == *7 ]] || [[ $perms == *6 ]]; then
            log_critical "System directory is world-writable: $dir ($perms)"
        elif [[ $perms == *75 ]] || [[ $perms == *77 ]]; then
            log_warning "System directory may be too permissive: $dir ($perms)"
        else
            log_good "$dir: $perms"
        fi
    fi
done

log ""

# 11. FILES MODIFIED IN LAST 7 DAYS IN SYSTEM DIRECTORIES
log "${BLUE}[11] RECENTLY MODIFIED SYSTEM FILES${NC}"
log "----------------------------------------"

log_info "Checking for recently modified files in system directories..."
recent_files=$(find /etc /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -30)

if [ -n "$recent_files" ]; then
    log "Recently modified system files (last 7 days, showing first 30):"
    echo "$recent_files" | while read file; do
        mtime=$(stat -c %y "$file" | cut -d' ' -f1)
        log "  $file (modified: $mtime)"
    done
else
    log "  No recently modified system files"
fi

log ""

# 12. LARGE FILES IN UNUSUAL LOCATIONS
log "${BLUE}[12] CHECKING FOR LARGE FILES IN UNUSUAL LOCATIONS${NC}"
log "----------------------------------------"

log_info "Searching for large files (>100MB) in /tmp, /var/tmp, /dev/shm..."
large_files=$(find /tmp /var/tmp /dev/shm -type f -size +100M 2>/dev/null)

if [ -n "$large_files" ]; then
    log_warning "Large files found:"
    echo "$large_files" | while read file; do
        size=$(du -h "$file" | cut -f1)
        log "  $file ($size)"
    done
else
    log_good "No unusually large files in temp directories"
fi

log ""

# SUMMARY
log "========================================"
log "  FILE PERMISSION AUDIT COMPLETE"
log "  Report saved to: $REPORT_FILE"
log "========================================"
log ""
log "CRITICAL ITEMS TO ADDRESS:"
log "1. Fix any world-readable /etc/shadow"
log "2. Review unusual SUID/SGID binaries"
log "3. Secure world-writable files outside temp directories"
log "4. Fix private SSH key permissions (should be 600)"
log "5. Review recently modified system files"
log ""
log "RECOMMENDED PERMISSIONS:"
log "  /etc/passwd: 644"
log "  /etc/shadow: 640 or 600"
log "  /etc/group: 644"
log "  /etc/gshadow: 640 or 600"
log "  ~/.ssh: 700"
log "  ~/.ssh/authorized_keys: 600 or 644"
log "  ~/.ssh/id_*: 600 (private keys)"
log "  /boot/grub/grub.cfg: 600"
log ""
