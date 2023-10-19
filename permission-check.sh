#To check if a user was successfully assigned permissions in AWS SSO
#!/bin/bash

INSTANCE_ARN="your-sso-instance-arn" # e.g., arn:aws:sso:::instance/sso-instance-id
USER_NAME="username-to-check"
ACCOUNT_ID="target-account-id" 
PERMISSION_SET_ARN="permission-set-arn-to-check"

# Fetch the user's ARN based on the username
USER_ARN=$(aws sso-admin list-users --instance-arn $INSTANCE_ARN --query "Users[?UserName=='$USER_NAME'].UserArn" --output text)

# If the user doesn't exist, exit
if [ -z "$USER_ARN" ]; then
    echo "User not found."
    exit 1
fi

# List account assignments for the user
ASSIGNMENT=$(aws sso-admin list-account-assignments --instance-arn $INSTANCE_ARN --account-id $ACCOUNT_ID --permission-set-arn $PERMISSION_SET_ARN --principal-type USER --principal-id $(echo $USER_ARN | awk -F/ '{print $NF}') --query "AccountAssignments[?PrincipalId=='$(echo $USER_ARN | awk -F/ '{print $NF}')']" --output text)

if [ -z "$ASSIGNMENT" ]; then
    echo "User $USER_NAME does NOT have the specified permission set in account $ACCOUNT_ID."
else
    echo "User $USER_NAME has the specified permission set in account $ACCOUNT_ID."
fi








#Certainly, if you wish to check if a user has been assigned a specific permission set within AWS SSO
#The script will output whether the user has been successfully assigned the specified permission set for the given AWS account in AWS SSO or not.
#!/bin/bash

# Variables
SSO_INSTANCE_ARN="YOUR_SSO_INSTANCE_ARN_HERE"
TARGET_ACCOUNT_ID="YOUR_TARGET_ACCOUNT_ID_HERE"
PERMISSION_SET_ARN="YOUR_PERMISSION_SET_ARN_HERE"
USERNAME_TO_CHECK="YOUR_USERNAME_HERE"

# Fetch the ARN of the user
USER_ARN=$(aws sso-admin list-instances --query "Instances[?InstanceArn=='$SSO_INSTANCE_ARN'].InstanceArn" --output text | xargs -I {} aws sso-admin list-users --instance-arn {} --query "Users[?UserName=='$USERNAME_TO_CHECK'].UserArn" --output text)

if [ -z "$USER_ARN" ]; then
    echo "User $USERNAME_TO_CHECK does not exist in AWS SSO Identity Store."
    exit 1
fi

# Check account assignments with the specified permission set for the user
ASSIGNMENTS=$(aws sso-admin list-account-assignments \
    --instance-arn $SSO_INSTANCE_ARN \
    --account-id $TARGET_ACCOUNT_ID \
    --principal-type USER \
    --principal-id $(echo $USER_ARN | cut -d'/' -f 6) \
    --query "AccountAssignments[?PrincipalId=='$(echo $USER_ARN | cut -d'/' -f 6)' && PermissionSetArn=='$PERMISSION_SET_ARN'].PermissionSetArn" \
    --output text)

if [ -z "$ASSIGNMENTS" ]; then
    echo "User $USERNAME_TO_CHECK does not have the permission set $PERMISSION_SET_ARN assigned in AWS SSO for account $TARGET_ACCOUNT_ID."
else
    echo "User $USERNAME_TO_CHECK has been successfully assigned the permission set $PERMISSION_SET_ARN in AWS SSO for account $TARGET_ACCOUNT_ID."
fi
