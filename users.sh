#!/bin/bash

# Check if file argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <user_list_file>"
    echo "File format: username [password] (password indicates admin)"
    exit 1
fi

USER_FILE="$1"

# Check if file exists
if [ ! -f "$USER_FILE" ]; then
    echo "Error: File '$USER_FILE' not found"
    exit 1
fi

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
echo "================================"
echo "USER AUDIT REPORT"
echo "================================"
echo

echo "1. UNAUTHORIZED USERS (on system but not in authorized list):"
if [ ${#unauthorized_users[@]} -eq 0 ]; then
    echo "   None"
else
    for user in "${unauthorized_users[@]}"; do
        echo "   - $user"
    done
fi
echo

echo "2. MISSING USERS (in authorized list but don't exist on system):"
if [ ${#missing_users[@]} -eq 0 ]; then
    echo "   None"
else
    for user in "${missing_users[@]}"; do
        echo "   - $user"
    done
fi
echo

echo "3. USERS WHO SHOULDN'T BE ADMIN (but are):"
if [ ${#should_not_be_admin[@]} -eq 0 ]; then
    echo "   None"
else
    for user in "${should_not_be_admin[@]}"; do
        echo "   - $user"
    done
fi
echo

echo "4. USERS WHO SHOULD BE ADMIN (but aren't):"
if [ ${#should_be_admin[@]} -eq 0 ]; then
    echo "   None"
else
    for user in "${should_be_admin[@]}"; do
        echo "   - $user"
    done
fi
echo

echo "================================"
echo "Audit complete"
echo "================================"
