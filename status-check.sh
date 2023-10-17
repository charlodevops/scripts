#!/bin/bash

INSTANCE_ARN="arn:aws:sso:::instance/ssoins-698759770ce5a35e"  # Replace with your actual Instance ARN
ACCOUNT_ID="6224-9686-9545"      # Replace with your actual Account ID

# 1. Check if a user exists in AWS SSO
check_user_exists() {
  local username="$1"
  user=$(aws sso list-users --query "join(',', Users[].UserName)" --output text)
  if [[ "$user" == *"$username"* ]]; then
    echo "User $username exists in AWS SSO."
    return 0
  else
    echo "User $username does not exist in AWS SSO."
    return 1
  fi
}

# 2. Check if a user has been added to an AWS account in AWS SSO
check_user_status() {
  local username="$1"
  user_status=$(aws sso-admin list-account-assignments --instance-arn $INSTANCE_ARN --account-id $ACCOUNT_ID --query "join(',', AccountAssignments[].PrincipalName)" --output text)
  if [[ "$user_status" == *"$username"* ]]; then
    echo "User $username has been added to the account in AWS SSO."
  else
    echo "User $username has NOT been added to the account in AWS SSO."
  fi
}

# Main Execution

read -p "Enter the username to check: " username

check_user_exists "$username" && check_user_status "$username"
