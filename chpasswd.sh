#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Prompt for the username
read -p "Enter the username to change the password for: " username

# Check if the user exists
if ! id "$username" &>/dev/null; then
    echo "User '$username' does not exist."
    exit 1
fi

# Prompt for the new password (hidden input)
read -s -p "Enter the new password for '$username': " new_password
echo
read -s -p "Confirm the new password: " confirm_password
echo

# Check if passwords match
if [[ "$new_password" != "$confirm_password" ]]; then
    echo "Passwords do not match. Please try again."
    exit 1
fi

# Change the user's password
echo -e "$new_password\n$new_password" | passwd "$username"

if [[ $? -eq 0 ]]; then
    echo "Password for '$username' successfully changed."
else
    echo "Failed to change password for '$username'."
    exit 1
fi

