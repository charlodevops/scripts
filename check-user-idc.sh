#!/bin/bash

# Function to check if a user exists in AWS SSO
check_user_exists() {
  local username="$1"
  user_data=$(aws identitystore list-users --identity-store-id #put_aws_identity_store_id)

  if echo "$user_data" | grep -q "\"UserName\": \"$username\""; then
    echo "User $username exists in AWS SSO."
    return 0
  else
    echo "User $username does not exist in AWS SSO."
    return 1
  fi
}

# Main Execution

read -p "Enter the username to check: " username
check_user_exists "$username"

