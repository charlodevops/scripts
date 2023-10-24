#!/bin/bash


read -p "enter the user name to test : " username
result=$(aws-sso-util admin lookup  user $username)

echo $result | grep -q  "NOT_FOUND"
if [ $? -eq 0 ]; then
    echo "The $username not found"
    exit
else
    echo "The user $username exists, checking permission sets. wait..."
    groups=$(aws identitystore list-groups --identity-store-id d-996707e2f3 | jq '.Groups | map({(.DisplayName): .GroupId}) | add')
    UserId=$(aws-sso-util admin lookup user  $username | awk 'NR>1 {print $2}')
    user_permission_set=$(aws-sso-util admin assignments --user $UserId | awk -F, 'NR==1{for(i=1; i<=NF; i++) {if ($i == "permission_set_name") age_col=i; if ($i == "target_name") city_col=i}} NR>1{print $age_col, $city_col}' > report.csv)
    echo "$groups" | jq -r '.[]' | while read -r GroupId; do
     MembershipExists=$(aws identitystore is-member-in-groups \
    --identity-store-id d-996707e2f3 \
    --member-id UserId=$UserId \
    --group-ids  $GroupId --no-paginate | jq '.Results[].MembershipExists')
    if [ "$MembershipExists" == "true" ]; then
        #echo "Found matching GroupId: $GroupId"
      group_permission_set=$(aws-sso-util admin assignments --group $GroupId  |  awk -F, 'NR==1{for(i=1; i<=NF; i++) {if ($i == "permission_set_name") age_col=i; if ($i == "target_name") city_col=i}} NR>1{print $age_col, $city_col}' >> report.csv)

    fi
    done

    if [[ ! -s report.csv ]]; then
    echo "No permission sets attached with user"
    else
    echo "Permission Sets Attached"
    sort -u report.csv
    fi
    
fi
