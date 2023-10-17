#!/bin/bash

check_user_exists() {
  local userid="$1"
  aws identitystore describe-user --identity-store-id d-996707e2f3 --user-id "$userid"
  echo "Checking if user $userid exists..."
}

check_user_permission() {
  local user_id="$1"
  # local $user_name="charles.bate@gmx.us"
  local instance_arn="arn:aws:sso:::instance/ssoins-698759770ce5a35e"

filtered_permission_sets=$(aws sso-admin list-permission-sets --instance-arn "$instance_arn")
  
  echo "Permission Sets for User with ID $user_id:"
  
  echo "$filtered_permission_sets"
}

echo "Welcome to the SSO User and Permission Checker."

read -p "Enter the userid: " userid
read -p "Enter 'exists' to check user existence or 'permission' to check permissions: " check_type

if [ "$check_type" == "exists" ]; then
  check_user_exists "$userid"
elif [ "$check_type" == "permission" ]; then
  check_user_permission "$userid"
else
  echo "Invalid check_type. Use 'exists' to check user existence or 'permission' to check permissions."
  exit 1
fi
