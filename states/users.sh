#!/bin/bash

# User Audit and Auto-Fix Script for Ubuntu/Mint
# Must be run as root for fixes

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if file argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <user_list_file> [--auto-fix]"
    echo "File format: username [password] (password indicates admin)"
    echo ""
    echo "Options:"
    echo "  --auto-fix    Automatically fix issues with user approval"
    exit 1
fi

USER_FILE="$1"
AUTO_FIX=0

# Check for auto-fix flag
if [ "$2" = "--auto-fix" ]; then
    AUTO_FIX=1
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Error: --auto-fix requires root privileges${NC}"
        echo "Please run with: sudo $0 $USER_FILE --auto-fix"
        exit 1
    fi
fi

# Check if file exists
if [ ! -f "$USER_FILE" ]; then
    echo "Error: File '$USER_FILE' not found"
    exit 1
fi

REPORT_FILE="user_audit_$(date +%Y%m%d_%H%M%S).txt"

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$REPORT_FILE"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$REPORT_FILE"
}

log_good() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$REPORT_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$REPORT_FILE"
}

# Arrays to store results
declare -a unauthorized_users
declare -a missing_users
declare -a should_not_be_admin
declare -a should_be_admin

# Get list of users who can use sudo (admin users)
get_admin_users() {
    getent group sudo | cut -d: -f4 | tr ',' '\n'
    getent group admin | cut -d: -f4 | tr ',' '\n'
}

admin_users=$(get_admin_users | sort -u)

log ""
log "========================================"
log "  USER AUDIT REPORT"
log "  Started: $(date)"
log "========================================"
log ""

# Read the authorized user file
while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Parse username and check if password field exists (indicates admin)
    username=$(echo "$line" | awk '{print $1}')
    should_be_admin_flag=$(echo "$line" | awk '{print $2}')
    
    # Check if user exists in /etc/passwd
    if getent passwd "$username" > /dev/null 2>&1; then
        # User exists - check admin status
        is_admin=$(echo "$admin_users" | grep -x "$username")
        
        if [ -n "$should_be_admin_flag" ]; then
            # User should be admin
            if [ -z "$is_admin" ]; then
                should_be_admin+=("$username")
            fi
        else
            # User should NOT be admin
            if [ -n "$is_admin" ]; then
                should_not_be_admin+=("$username")
            fi
        fi
    else
        # User doesn't exist
        missing_users+=("$username")
    fi
done < "$USER_FILE"

# Find unauthorized users (exist on system but not in authorized file)
while IFS=: read -r username _ uid _; do
    # Skip system users (UID < 1000) and nobody
    [ "$uid" -lt 1000 ] && continue
    [ "$username" = "nobody" ] && continue
    
    # Check if user is in authorized file
    if ! grep -q "^$username\b" "$USER_FILE"; then
        unauthorized_users+=("$username")
    fi
done < /etc/passwd

# Print results
log "================================"
log "1. UNAUTHORIZED USERS (on system but not in authorized list):"
log "================================"
if [ ${#unauthorized_users[@]} -eq 0 ]; then
    log_good "None"
else
    for user in "${unauthorized_users[@]}"; do
        log_warning "$user"
    done
fi
log ""

log "================================"
log "2. MISSING USERS (in authorized list but don't exist on system):"
log "================================"
if [ ${#missing_users[@]} -eq 0 ]; then
    log_good "None"
else
    for user in "${missing_users[@]}"; do
        log_warning "$user"
    done
fi
log ""

log "================================"
log "3. USERS WHO SHOULDN'T BE ADMIN (but are):"
log "================================"
if [ ${#should_not_be_admin[@]} -eq 0 ]; then
    log_good "None"
else
    for user in "${should_not_be_admin[@]}"; do
        log_critical "$user"
    done
fi
log ""

log "================================"
log "4. USERS WHO SHOULD BE ADMIN (but aren't):"
log "================================"
if [ ${#should_be_admin[@]} -eq 0 ]; then
    log_good "None"
else
    for user in "${should_be_admin[@]}"; do
        log_critical "$user"
    done
fi
log ""

# Count total issues
total_issues=$(( ${#unauthorized_users[@]} + ${#missing_users[@]} + ${#should_not_be_admin[@]} + ${#should_be_admin[@]} ))

log "================================"
log "SUMMARY: $total_issues issue(s) found"
log "Report saved to: $REPORT_FILE"
log "================================"
log ""

# AUTO-FIX SECTION
if [ $AUTO_FIX -eq 1 ] && [ $total_issues -gt 0 ]; then
    log ""
    log "${BLUE}========================================"
    log "  AUTO-FIX MODE"
    log "========================================${NC}"
    log ""
    
    # Create a backup of current state
    BACKUP_FILE="user_backup_$(date +%Y%m%d_%H%M%S).txt"
    log_info "Creating backup of current user state..."
    log "Backup file: $BACKUP_FILE"
    
    # Backup current users and their groups
    {
        echo "# User Backup - $(date)"
        echo "# Format: username:uid:groups"
        while IFS=: read -r username _ uid _; do
            [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ] && {
                groups=$(groups "$username" | cut -d: -f2)
                echo "$username:$uid:$groups"
            }
        done < /etc/passwd
    } > "$BACKUP_FILE"
    
    log_good "Backup created: $BACKUP_FILE"
    log ""
    
    # Fix 1: Remove unauthorized users
    if [ ${#unauthorized_users[@]} -gt 0 ]; then
        log "${BLUE}[FIX 1] UNAUTHORIZED USERS${NC}"
        log "----------------------------------------"
        log "The following users are on the system but NOT in your authorized list:"
        for user in "${unauthorized_users[@]}"; do
            log "  - $user"
        done
        log ""
        echo -n "Do you want to REMOVE these users? [y/N]: "
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            for user in "${unauthorized_users[@]}"; do
                log_info "Removing user: $user"
                
                # Ask whether to remove home directory
                echo -n "  Remove home directory for $user? [y/N]: "
                read -r remove_home
                
                if [[ "$remove_home" =~ ^[Yy]$ ]]; then
                    userdel -r "$user" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        log_good "Removed $user (including home directory)"
                    else
                        log_warning "Failed to remove $user"
                    fi
                else
                    userdel "$user" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        log_good "Removed $user (home directory preserved)"
                    else
                        log_warning "Failed to remove $user"
                    fi
                fi
            done
        else
            log "Skipped removing unauthorized users"
        fi
        log ""
    fi
    
    # Fix 2: Create missing users
    if [ ${#missing_users[@]} -gt 0 ]; then
        log "${BLUE}[FIX 2] MISSING USERS${NC}"
        log "----------------------------------------"
        log "The following users are in your authorized list but DON'T exist:"
        for user in "${missing_users[@]}"; do
            log "  - $user"
        done
        log ""
        echo -n "Do you want to CREATE these users? [y/N]: "
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            for user in "${missing_users[@]}"; do
                log_info "Creating user: $user"
                
                # Create user with home directory
                useradd -m -s /bin/bash "$user" 2>/dev/null
                
                if [ $? -eq 0 ]; then
                    log_good "Created user: $user"
                    
                    # Set password
                    log_info "Please set a password for $user:"
                    passwd "$user"
                    
                    # Check if this user should be admin
                    should_be_admin_check=$(grep "^$user\s" "$USER_FILE" | awk '{print $2}')
                    if [ -n "$should_be_admin_check" ]; then
                        log_info "Adding $user to sudo group (admin)..."
                        usermod -aG sudo "$user"
                        log_good "$user added to sudo group"
                    fi
                else
                    log_warning "Failed to create user: $user"
                fi
            done
        else
            log "Skipped creating missing users"
        fi
        log ""
    fi
    
    # Fix 3: Remove admin privileges from users who shouldn't have them
    if [ ${#should_not_be_admin[@]} -gt 0 ]; then
        log "${BLUE}[FIX 3] REMOVE ADMIN PRIVILEGES${NC}"
        log "----------------------------------------"
        log "The following users have admin rights but SHOULDN'T:"
        for user in "${should_not_be_admin[@]}"; do
            log "  - $user"
        done
        log ""
        echo -n "Do you want to REMOVE admin privileges from these users? [y/N]: "
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            for user in "${should_not_be_admin[@]}"; do
                log_info "Removing admin privileges from: $user"
                
                # Remove from sudo group
                gpasswd -d "$user" sudo 2>/dev/null
                # Also remove from admin group (older Ubuntu/Debian)
                gpasswd -d "$user" admin 2>/dev/null
                
                if [ $? -eq 0 ]; then
                    log_good "Removed admin privileges from: $user"
                else
                    log_warning "Failed to remove admin privileges from: $user"
                fi
            done
        else
            log "Skipped removing admin privileges"
        fi
        log ""
    fi
    
    # Fix 4: Add admin privileges to users who should have them
    if [ ${#should_be_admin[@]} -gt 0 ]; then
        log "${BLUE}[FIX 4] ADD ADMIN PRIVILEGES${NC}"
        log "----------------------------------------"
        log "The following users SHOULD have admin rights but don't:"
        for user in "${should_be_admin[@]}"; do
            log "  - $user"
        done
        log ""
        echo -n "Do you want to ADD admin privileges to these users? [y/N]: "
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            for user in "${should_be_admin[@]}"; do
                log_info "Adding admin privileges to: $user"
                
                # Add to sudo group
                usermod -aG sudo "$user"
                
                if [ $? -eq 0 ]; then
                    log_good "Added admin privileges to: $user"
                else
                    log_warning "Failed to add admin privileges to: $user"
                fi
            done
        else
            log "Skipped adding admin privileges"
        fi
        log ""
    fi
    
    # Final summary
    log ""
    log "${BLUE}========================================"
    log "  AUTO-FIX COMPLETE"
    log "========================================${NC}"
    log ""
    log_info "Changes have been applied!"
    log_info "Backup saved to: $BACKUP_FILE"
    log ""
    log "To restore from backup if needed, you can:"
    log "  - Review the backup file to see previous state"
    log "  - Manually recreate users from the backup"
    log "  - Use the userdel/useradd commands as needed"
    log ""
    
elif [ $AUTO_FIX -eq 1 ] && [ $total_issues -eq 0 ]; then
    log ""
    log_good "No issues found - no fixes needed!"
    log ""
elif [ $AUTO_FIX -eq 0 ] && [ $total_issues -gt 0 ]; then
    log ""
    log_info "To automatically fix these issues, run:"
    log "  sudo $0 $USER_FILE --auto-fix"
    log ""
fi
