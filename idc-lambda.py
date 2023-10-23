import boto3
import json
import time
import http.client
import os
import logging
import json

log_level = str(os.environ.get('LOG_LEVEL')).upper()
if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
    log_level = 'ERROR'
log = logging.getLogger()
log.setLevel(log_level)

from aws_lambda_powertools.event_handler.api_gateway import (
    ApiGatewayResolver,
    ProxyEventType,
    Response,
)
global_context = None
idc_client = boto3.client('identitystore')
sso_client = boto3.client('sso-admin')
secret_client = boto3.client('secretsmanager')
org_client = boto3.client('organizations')
instance_arn = 'arn:aws:sso:::instance/ssoins-79071ef5f2a874d9'
idc_id="d-9267420026"
app = ApiGatewayResolver(proxy_type=ProxyEventType.APIGatewayProxyEventV2)

def check_status(describe_status,req_id):
    if(describe_status=="create_account_assignment"):
        response = sso_client.describe_account_assignment_creation_status(
            InstanceArn=instance_arn,
            AccountAssignmentCreationRequestId=req_id
        )
        return response
    elif(describe_status=="delete_account_assignment"):
        response = sso_client.describe_account_assignment_deletion_status(
            InstanceArn=instance_arn,
            AccountAssignmentDeletionRequestId=req_id
        )
        return response
    else:
        return None


def check_user_status(response_user):
    user_id=response_user['UserId']
    bearer_token = os.environ.get('token')
    target_host='scim.us-west-2.amazonaws.com'
    scim_endpoint = f"/Nv827e42973-374e-4287-95e8-88200f5e34a2/scim/v2/Users/{user_id}"
    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }
    try:
        conn = http.client.HTTPSConnection(target_host)
        conn.request("GET", scim_endpoint, headers=headers)
        response = conn.getresponse()
        if response.status == 200:
            data = response.read()
            response_json = json.loads(data.decode('utf-8'))
            if(response_json['active']==True):
                return True
        else:
            log.error(f"HTTP Request failed with status code {response.status} {response.read()}")


    except Exception as e:
        log.error(f"Error get request failed: Message - {e}")
    return False

    

def getUserId(username):
    try:
        response_user=idc_client.get_user_id(
            IdentityStoreId=idc_id,
            AlternateIdentifier={
                'UniqueAttribute': {
                    'AttributePath': 'emails.value',
                    'AttributeValue': f"{username}"
                }    
        })
        if(check_user_status(response_user)):
            log.info("User found in IDC and its status is enabled as well")
            return response_user
        
    except Exception as e:
        log.error(e)
    return None

def getGroupId(group_name):
    try:
        response_group_id=idc_client.get_group_id(
            IdentityStoreId=idc_id,
            AlternateIdentifier={
                'UniqueAttribute': {
                    'AttributePath': 'displayName',
                    'AttributeValue': f"{group_name}"
                }    
        })
        log.info(f"Group {group_name} found in IDC")
        return response_group_id 
    except Exception as e:
        log.error(f"Group {group_name} not found. Error - {e}")    
    return None

def getMembershipId(group_id,user_id):
    try:
        response_membership_id=idc_client.get_group_membership_id(
            IdentityStoreId=idc_id,
            GroupId=group_id,
            MemberId={
                'UserId': user_id
        })
        return response_membership_id 
    except Exception as e:
        return None

def assign_all_perm_to_grp_in_acc(permissions,group_name,acc):
    request_ids={}
    response_grp=getGroupId(group_name)
    if(response_grp is None):
        return sendResponse("failure",f"Failed to add group {group_name}. Error - Group Not found in IdentityCenter. Automation ended in failure.")
    for perm in permissions:
        log.info(f"Adding permission {perm} to {group_name} in {acc}")
        try:
            response_acc_assign = sso_client.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=acc,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=perm,
                PrincipalType='GROUP',
                PrincipalId=response_grp['GroupId']
            )
            if(response_acc_assign['ResponseMetadata']['HTTPStatusCode']):
                acc_assignment_status=response_acc_assign['AccountAssignmentCreationStatus']['Status']
                acc_assignment_req_id=response_acc_assign['AccountAssignmentCreationStatus']['RequestId']
                if(acc_assignment_status!="FAILED" and len(acc_assignment_req_id)>0):
                    request_ids[perm]=acc_assignment_req_id
                else:
                    return sendResponse("failure",f"Failed to add permission to Group. Error - {acc_assignment_status} State . Please reach out to CIAS Team")
                    
            else:
                return sendResponse("failure",f"Failed to add permission to Group. Error - {response_acc_assign['ResponseMetadata']['HTTPStatusCode']} code. Please reach out to CIAS Team")
                    
        except Exception as e:
            return sendResponse("failure",f"Failed to add permission to Group. Error - An Error Occurred. Please reach out to CIAS Team - {e}")

    status_msg=""
    for key, value in request_ids.items():
        perm=key.split("/")[-1]
        log.info(f"Checking status of {perm}")
        retry_count=0
        while retry_count!=5:
            retry_count+=1
            time.sleep(2)
            user_assignment_reponse=check_status("create_account_assignment",value)
            user_assignment_status=user_assignment_reponse['AccountAssignmentCreationStatus']['Status']
            if(user_assignment_status=="FAILED"):
                failure_reason=user_assignment_reponse['AccountAssignmentCreationStatus']['FailureReason']
                return sendResponse("failure",f"Failure to add permission {perm} to {group_name} in {acc}. Error - {failure_reason}. Exiting automation")
            elif(user_assignment_status=="SUCCEEDED"):
                log.info(f"Permission {perm} add to {group_name} in {acc}")
                break
        
    return sendResponse("success",f"Group {group_name} added to account {acc} successfully. All permission sets assigned. {status_msg}")

def sendResponse(status, message):
    log_stream_name="Error Occured, unable to find the log stream name"
    global global_context
    if global_context:
        log_stream_name = global_context.log_stream_name
    if(status=="success"):
        success_response = {
            "statusCode": 200,
            "body": json.dumps({"message": message,"logs":log_stream_name})
        }
        log.info(f"Automation executed successfully. Message - {message}")
        return Response(status_code=success_response["statusCode"],content_type="application/json",body=success_response["body"])
    else:
        failure_response = {
            "statusCode": 404,
            "body": json.dumps({"message": message,"logs":log_stream_name})
        }
        log.error(f"Automation ended in failure. Message {message}")
        return Response(status_code=failure_response["statusCode"],content_type="application/json",body=failure_response["body"])
    


@app.post('/add-permission-to-users') 
def addPermToUser():
    username = app.current_event.get_query_string_value(name="user", default_value=None)
    permission_set_id = app.current_event.get_query_string_value(name="permissionSetArn", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    if(username is None or permission_set_id is None or acc is None):
        return sendResponse("failure",f"Failed to add username {username}. Error - Expected Values not provided.")
    log.info("Required values found")
    permission_set_arn = f"arn:aws:sso:::permissionSet/ssoins-79071ef5f2a874d9/{permission_set_id}"
    
    
    response_user=getUserId(username)
    if(response_user is None):
        return sendResponse("failure",f"Failed to add username {username}. Error - User Not found in IdentityCenter. Automation ended in failure.")
    
        
    
    try:
        response_acc_assign = sso_client.create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=acc,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType='USER',
            PrincipalId=response_user['UserId']
        )
        log.info(f"Assignment created for {username}. Assignment is in progress right now")
        if(response_acc_assign['ResponseMetadata']['HTTPStatusCode']):
            user_assignment_status=response_acc_assign['AccountAssignmentCreationStatus']['Status']
            user_assignment_req_id=response_acc_assign['AccountAssignmentCreationStatus']['RequestId']
            if(user_assignment_status=="FAILED"):
                return Response(status_code=404,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="SUCCEEDED"):
                return Response(status_code=200,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="IN_PROGRESS"):
                retry_count=0
                while retry_count!=5:
                    retry_count+=1
                    time.sleep(2)
                    user_assignment_reponse=check_status("create_account_assignment",user_assignment_req_id)
                    user_assignment_status=user_assignment_reponse['AccountAssignmentCreationStatus']['Status']
                    if(user_assignment_status=="FAILED"):
                        failure_reason=user_assignment_reponse['AccountAssignmentCreationStatus']['FailureReason']
                        return sendResponse("failure",f"Failed to add username. Error - {failure_reason}")
                    elif(user_assignment_status=="SUCCEEDED"):
                        log.info(f"Assignment was successfull. {username} added to {acc} on {permission_set_id}")
                        return sendResponse("success",f"User {username} added successfully.")
                    log.info(f"Assignment still in progress")
        return sendResponse("failure",f"Failed to add permission to username. Error - An Error Occurred. Please reach out to CIAS Team")
    except Exception as e:
        return sendResponse("failure",f"Failed to add permission to username. Error - An Error Occurred. Please reach out to CIAS Team - {e}")
        

@app.post('/remove-permission-from-users') 
def removePermFromUser():
    username = app.current_event.get_query_string_value(name="user", default_value=None)
    permission_set_id = app.current_event.get_query_string_value(name="permissionSetArn", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    
    if(username is None or permission_set_id is None or acc is None):
        return sendResponse("failure",f"Failed to add username {username}. Error - Expected Values not provided.")
    log.info("Required values found")    
    
    permission_set_arn = f"arn:aws:sso:::permissionSet/ssoins-79071ef5f2a874d9/{permission_set_id}"
    
    response_user=getUserId(username)
    if(response_user is None):
        return sendResponse("failure",f"Failed to add username {username}. Error - User Not found in IdentityCenter. Automation ended in failure.")
    
    try:
        response_acc_user_delete = sso_client.delete_account_assignment(
            InstanceArn=instance_arn,
            TargetId=acc,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType='USER',
            PrincipalId=response_user['UserId']
        )
        log.info(f"Assignment created for {username}. Deletion Assignment is in progress right now")
        if(response_acc_user_delete['ResponseMetadata']['HTTPStatusCode']):
            user_assignment_status=response_acc_user_delete['AccountAssignmentDeletionStatus']['Status']
            user_assignment_req_id=response_acc_user_delete['AccountAssignmentDeletionStatus']['RequestId']
            if(user_assignment_status=="FAILED"):
                return Response(status_code=404,content_type="application/json",body=json.dumps(response_acc_delete, default=str))
    
            if(user_assignment_status=="SUCCEEDED"):
                return Response(status_code=200,content_type="application/json",body=json.dumps(response_acc_delete, default=str))
    
            if(user_assignment_status=="IN_PROGRESS"):
                retry_count=0
                while retry_count!=5:
                    retry_count+=1
                    time.sleep(2)
                    user_delete_response=check_status("delete_account_assignment",user_assignment_req_id)
                    user_assignment_status=user_delete_response['AccountAssignmentDeletionStatus']['Status']
                    if(user_assignment_status=="FAILED"):
                        failure_reason=user_delete_response['AccountAssignmentDeletionStatus']['FailureReason']
                        if("EntitlementItem doesn't exist" in failure_reason):
                            failure_reason = "User was never associated with the policy. Please check the policy and account you want to remove from user. Automation completed"
                        
                        return sendResponse("failure",f"Failed to remove username {username}. Error - {failure_reason}")
                    elif(user_assignment_status=="SUCCEEDED"):
                        log.info(f"Assignment was successfull. {username} removed from {acc} on {permission_set_id}")
                        return sendResponse("success",f"User {username} removed successfully.")
                    log.info(f"Assignment still in progress")
                            
        return sendResponse("failure",f"Failed to remove permission from username. Error - An Error Occurred. Please reach out to CIAS Team")
    except Exception as e:
        return sendResponse("failure",f"Failed to remove permission from username. Error - An Error Occurred. Please reach out to CIAS Team - {e}")
        


@app.post('/create-idc-group') 
def create_idc_group():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    if(group_name is None):
        return sendResponse("failure",f"Failed to create group. Error - Group Name not provided")
    log.info("Required values found")    
    try: 
        response_create_grp = idc_client.create_group(
            IdentityStoreId=idc_id,
            DisplayName=group_name,
            Description=group_name,
        )
        if(response_create_grp['ResponseMetadata']['HTTPStatusCode']==200):
            return sendResponse("success",f"Group {group_name} created successfully.")
            
    except Exception as e:
        return sendResponse("failure",f"Failed to create group. Please reach out to CIAS Team. Error - {e}")
    return sendResponse("failure",f"Failed to create group. Please reach out to CIAS Team.")
        


@app.post('/remove-idc-group') 
def remove_idc_group():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    if(group_name is None):
        return sendResponse("failure",f"Failed to remove group. Error - Group Name not provided")
    log.info("Required values found")
    
    response_group_id=getGroupId(group_name)
    if(response_group_id is None):
        return sendResponse("failure",f"Failed to remove group. Error - Group {group_name} not found")
    
        
    try:
        response_delete_grp = idc_client.delete_group(
            IdentityStoreId=idc_id,
            GroupId=response_group_id['GroupId'],
        )
        
        if(response_delete_grp['ResponseMetadata']['HTTPStatusCode']==200):
            return sendResponse("success",f"Group {group_name} deleted successfully.")
            
        return sendResponse("failure",f"Failed to remove group - {group_name}. Please reach out to CIAS Team. {response_delete_grp}")
    except Exception as e:
        return sendResponse("failure",f"Failed to remove group - {group_name}. Please reach out to CIAS Team. Error - {e} ")
    

@app.post('/add-users-to-group') 
def add_user_to_group(): 
    username = app.current_event.get_query_string_value(name="user", default_value=None)
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    if(username is None or group_name is None):
        return sendResponse("failure",f"Failed to add username to group. Error - Expected Values not provided.")
    log.info("Required values found")
    response_user=getUserId(username)
    response_group=getGroupId(group_name)
    
    if(response_group is None or response_user is None):
        return sendResponse("failure",f"Failed to add username to group. Error - Group or User not found in IDC.")
    
    try:    
        response_grp_member = idc_client.create_group_membership(
            IdentityStoreId=idc_id,
            GroupId=response_group['GroupId'],
            MemberId={
                'UserId': response_user['UserId']
            }
        )
        if(response_grp_member['ResponseMetadata']['HTTPStatusCode']==200):
            return sendResponse("success",f"User {username} added to group {group_name} successfully")
        
        return sendResponse("failure",f"Failed to add user {username} to group - {group_name}. Please reach out to CIAS Team.")
    except Exception as e:
        return sendResponse("failure",f"Failed to add user {username} to group - {group_name}. Please reach out to CIAS Team. Error - {e} ")
            

@app.post('/remove-user-from-grp') 
def remove_user_from_group():
    username = app.current_event.get_query_string_value(name="user", default_value=None)
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    if(username is None or group_name is None):
        return sendResponse("failure",f"Failed to remove username to group. Error - Expected Values not provided.")
    log.info("Required values found")
    response_user=getUserId(username)
    response_group=getGroupId(group_name)
    
    if(response_group is None or response_user is None):
        return sendResponse("failure",f"Failed to add username to group. Error - Group or User not found in IDC.")
    
    response_membership_id=getMembershipId(response_group['GroupId'],response_user['UserId'])
    if(response_membership_id is None):
        return sendResponse("failure",f"Failed to add username to group. Error - Group or User not found in IDC.")
    log.info(f"Membership found between {username} and {group_name}")
    
    try:
        response_remove_membership = idc_client.delete_group_membership(
            IdentityStoreId=idc_id,
            MembershipId=response_membership_id['MembershipId']
        )
        if(response_remove_membership['ResponseMetadata']['HTTPStatusCode']==200):
            return sendResponse("success",f"User {username} removed from group {group_name} successfully")
            
        return sendResponse("failure",f"Failed to remove user {username} from {group_name}. Please reach out to CIAS Team.")
    except Exception as e:
        return sendResponse("failure",f"Failed to remove user {username} from {group_name}. Please reach out to CIAS Team. Error - {e} ")


@app.post('/add-permission-to-grp') 
def addPermToGroup():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    permission_set_id = app.current_event.get_query_string_value(name="permissionSetArn", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    return addPermToGroupConfig(group_name,permission_set_id,acc)

def addPermToGroupConfig(group_name,permission_set_id,acc):
    if(group_name is None or permission_set_id is None or acc is None):
        return sendResponse("failure",f"Failed to add group {group_name}. Error - Expected Values not provided.")
    log.info("Required values found")
    if("arn:aws:sso:::" not in permission_set_id):
        permission_set_arn = f"arn:aws:sso:::permissionSet/ssoins-79071ef5f2a874d9/{permission_set_id}"
    else:
        permission_set_arn=permission_set_id
    
    
    response_grp=getGroupId(group_name)
    if(response_grp is None):
        return sendResponse("failure",f"Failed to add group {group_name}. Error - Group Not found in IdentityCenter. Automation ended in failure.")
        
    try:
        response_acc_assign = sso_client.create_account_assignment(
            InstanceArn='arn:aws:sso:::instance/ssoins-79071ef5f2a874d9',
            TargetId=acc,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType='GROUP',
            PrincipalId=response_grp['GroupId']
        )
        log.info(f"Assignment created for {group_name}. Assignment is in progress right now")
        if(response_acc_assign['ResponseMetadata']['HTTPStatusCode']):
            user_assignment_status=response_acc_assign['AccountAssignmentCreationStatus']['Status']
            user_assignment_req_id=response_acc_assign['AccountAssignmentCreationStatus']['RequestId']
            if(user_assignment_status=="FAILED"):
                return Response(status_code=404,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="SUCCEEDED"):
                return Response(status_code=200,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="IN_PROGRESS"):
                retry_count=0
                while retry_count!=5:
                    retry_count+=1
                    time.sleep(2)
                    user_assignment_reponse=check_status("create_account_assignment",user_assignment_req_id)
                    user_assignment_status=user_assignment_reponse['AccountAssignmentCreationStatus']['Status']
                    if(user_assignment_status=="FAILED"):
                        failure_reason=user_assignment_reponse['AccountAssignmentCreationStatus']['FailureReason']
                        return sendResponse("failure",f"Failed to add group. Error - {failure_reason}")
                    elif(user_assignment_status=="SUCCEEDED"):
                        return sendResponse("success",f"Permission {permission_set_id} added to {group_name} in {acc} added successfully.")
                    log.info(f"Assignment still in progress")
                            
        return sendResponse("failure",f"Failed to add permission to group. Error - An Error Occurred. Please reach out to CIAS Team")
    except Exception as e:
        return sendResponse("failure",f"Failed to add permission to group. Error - An Error Occurred. Please reach out to CIAS Team - {e}")
    

@app.post('/remove-permission-from-grp') 
def removePermFromGroup():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    permission_set_id = app.current_event.get_query_string_value(name="permissionSetArn", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    if(group_name is None or permission_set_id is None or acc is None):
        return sendResponse("failure",f"Failed to remove group {group_name}. Error - Expected Values not provided.")
    log.info("Required values found")
    permission_set_arn = f"arn:aws:sso:::permissionSet/ssoins-79071ef5f2a874d9/{permission_set_id}"
    
    
    response_grp=getGroupId(group_name)
    if(response_grp is None):
        return sendResponse("failure",f"Failed to add group {group_name}. Error - Group Not found in IdentityCenter. Automation ended in failure.")
        
    
    try:
        response_acc_assign = sso_client.delete_account_assignment(
            InstanceArn='arn:aws:sso:::instance/ssoins-79071ef5f2a874d9',
            TargetId=acc,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType='GROUP',
            PrincipalId=response_grp['GroupId']
        )
        log.info(f"Assignment created for {group_name}. Deletion Assignment is in progress right now")
        if(response_acc_assign['ResponseMetadata']['HTTPStatusCode']):
            user_assignment_status=response_acc_assign['AccountAssignmentDeletionStatus']['Status']
            user_assignment_req_id=response_acc_assign['AccountAssignmentDeletionStatus']['RequestId']
            if(user_assignment_status=="FAILED"):
                return Response(status_code=404,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="SUCCEEDED"):
                return Response(status_code=200,content_type="application/json",body=json.dumps(response_acc_assign, default=str))
    
            elif(user_assignment_status=="IN_PROGRESS"):
                retry_count=0
                while retry_count!=5:
                    retry_count+=1
                    time.sleep(2)
                    user_assignment_reponse=check_status("delete_account_assignment",user_assignment_req_id)
                    user_assignment_status=user_assignment_reponse['AccountAssignmentDeletionStatus']['Status']
                    if(user_assignment_status=="FAILED"):
                        failure_reason=user_assignment_reponse['AccountAssignmentDeletionStatus']['FailureReason']
                        if("EntitlementItem doesn't exist" in failure_reason):
                            failure_reason = f"Group {group_name} was never associated with the policy. Please check the policy and account you want to remove from group. Automation completed"
                        return sendResponse("failure",f"Failed to remove permission. Error - {failure_reason}")
                    elif(user_assignment_status=="SUCCEEDED"):
                        return sendResponse("success",f"Permission {permission_set_id} removed from group {group_name} in account {acc} successfully.")
                            
        return sendResponse("failure",f"Failed to remove permission from group. Error - An Error Occurred. Please reach out to CIAS Team")
    except Exception as e:
        return sendResponse("failure",f"Failed to remove permission from group. Error - An Error Occurred. Please reach out to CIAS Team - {e}")
        

@app.post('/add-grp-to-account') 
def add_group_to_account():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    if(group_name is None or acc is None):
        return sendResponse("failure",f"Failed to add group. Error - Expected Values not provided.")
    try: 
        response_add_grp = sso_client.list_permission_sets_provisioned_to_account(
            AccountId=acc,
            InstanceArn=instance_arn,
            ProvisioningStatus='LATEST_PERMISSION_SET_PROVISIONED'
        )
        all_permissions=response_add_grp['PermissionSets']
        return assign_all_perm_to_grp_in_acc(all_permissions,group_name,acc)
        
    except Exception as e:
        return sendResponse("failure",f"Failed to add group. Please reach out to CIAS Team. Error - {e}")


def remove_all_perm_to_grp_in_acc(permissions,group_name,acc):
    request_ids={}
    response_grp=getGroupId(group_name)
    if(response_grp is None):
        return sendResponse("failure",f"Failed to add group {group_name}. Error - Group Not found in IdentityCenter. Automation ended in failure.")
    for perm in permissions:
        log.info(f"Removing permission {perm} from {group_name} in {acc}")
        try:
            response_acc_assign = sso_client.delete_account_assignment(
                InstanceArn=instance_arn,
                TargetId=acc,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=perm,
                PrincipalType='GROUP',
                PrincipalId=response_grp['GroupId']
            )
            if(response_acc_assign['ResponseMetadata']['HTTPStatusCode']):
                acc_remove_status=response_acc_assign['AccountAssignmentDeletionStatus']['Status']
                acc_remove_req_id=response_acc_assign['AccountAssignmentDeletionStatus']['RequestId']
                if(acc_remove_status!="FAILED" and len(acc_remove_req_id)>0):
                    request_ids[perm]=acc_remove_req_id
                else:
                    return sendResponse("failure",f"Failed to remove permission from Group. Error - {acc_remove_status} State . Please reach out to CIAS Team")
                    
            else:
                return sendResponse("failure",f"Failed to remove permission from Group. Error - {response_acc_assign['ResponseMetadata']['HTTPStatusCode']} code. Please reach out to CIAS Team")
                    
        except Exception as e:
            return sendResponse("failure",f"Failed to remove permission from Group. Error - An Error Occurred. Please reach out to CIAS Team - {e}")

    for key, value in request_ids.items():
        perm=key.split("/")[-1]
        log.info(f"Checking status of {perm}")
        retry_count=0
        while retry_count!=5:
            retry_count+=1
            time.sleep(2)
            grp_delete_response=check_status("delete_account_assignment",value)
            grp_delete_response_status=grp_delete_response['AccountAssignmentDeletionStatus']['Status']
            if(grp_delete_response_status=="FAILED"):
                failure_reason=grp_delete_response['AccountAssignmentDeletionStatus']['FailureReason']
                if("EntitlementItem doesn't exist" in failure_reason):
                    log.info(f"Permission {perm} was never associated with {group_name} in {acc}")
                    break
                else:
                    return sendResponse("failure",f"Failure to add permission {perm} to {group_name} in {acc}. Error - {failure_reason}. Exiting automation")
            elif(grp_delete_response_status=="SUCCEEDED"):
                log.info(f"Permission {perm} remove from {group_name} in {acc}")
                break
        
    return sendResponse("success",f"Group {group_name} removed from account {acc} successfully. All permission sets removed.")


@app.post('/remove-grp-from-account') 
def remove_group_from_account():
    group_name = app.current_event.get_query_string_value(name="group_name", default_value=None)
    acc= app.current_event.get_query_string_value(name="account_id", default_value=None)
    if(group_name is None or acc is None):
        return sendResponse("failure",f"Failed to remove group. Error - Expected Values not provided.")
    try: 
        response_add_grp = sso_client.list_permission_sets_provisioned_to_account(
            AccountId=acc,
            InstanceArn=instance_arn,
            ProvisioningStatus='LATEST_PERMISSION_SET_PROVISIONED'
        )
        all_permissions=response_add_grp['PermissionSets']
        return remove_all_perm_to_grp_in_acc(all_permissions,group_name,acc)
        
    except Exception as e:
        return sendResponse("failure",f"Failed to add group. Please reach out to CIAS Team. Error - {e}")


def delete_user_from_idc(userId):
    log.info(f"A user with userID {userId} will be deleted from IDC. All of his access will be removed")
    log.info("Below are the user details")
    
    try:
        user_details=idc_client.describe_user(
            IdentityStoreId=idc_id,
            UserId=userId
        )
        log.info(f"Usernmae - {user_details['UserName']}\nDisplayName - {user_details['DisplayName']}\nEmail - {user_details['Emails'][0]['Value']}")
        
        user_delete_response=idc_client.delete_user(
            IdentityStoreId=idc_id,
            UserId=userId
        )
        if(user_delete_response['ResponseMetadata']['HTTPStatusCode']==200):
            log.info(f"User {user_details['Emails'][0]['Value']} deleted successfully")
        
        return sendResponse("success",f"User deleted from IDC")
    except Exception as e:
        log.error(e)
    return sendResponse("failure",f"Unable to delete user from IDC.")
    
def create_account(create_account_id):
    try:
        log.info(f"This is the account creation request id {create_account_id}")
        log.info("Checking the status of the account creation")
        counter=0
        org_client=boto3.client('organizations')
        account_id=""
        while(counter!=5):
            counter+=1
            time.sleep(5)
            response_acc_create = org_client.describe_create_account_status(
                CreateAccountRequestId=str(create_account_id)
            )
            log.info(response_acc_create)
            if(response_acc_create['CreateAccountStatus']['State']=='SUCCEEDED'):
                account_id=response_acc_create['CreateAccountStatus']['AccountId']
                accountName=response_acc_create['CreateAccountStatus']['AccountName']
                log.info(f"Account, created successfully, Here are the details: AccountId - {account_id} Account Name - {accountName}")
                break
            if(response_acc_create['CreateAccountStatus']['State']=='FAILED'):
                log.info("The create account status resulted in failure. Quitting automation")
                return sendResponse("failure",f"The create account status resulted in failure. Please reach out to CIAS Team.")
        if(account_id!=""):
            log.info(f"We have the account id and we can proceed to add all the permissions to it {account_id}")
            all_perm_sets=sso_client.list_permission_sets(
                InstanceArn=instance_arn,
            )
            all_perm_sets=all_perm_sets['PermissionSets']
            permission_to_add_to_grps={}
            for perm in all_perm_sets:
                log.info(f"Checking {perm} tags")
                tag_perm = sso_client.list_tags_for_resource(
                    InstanceArn=instance_arn,
                    ResourceArn=perm
                )
                permission_required_value = next((tag['Value'] for tag in tag_perm.get('Tags', []) if tag.get('Key') == 'permission-required'), None)
                groups_to_be_assigned = next((tag['Value'] for tag in tag_perm.get('Tags', []) if tag.get('Key') == 'groups-to-add'), None)
                if(groups_to_be_assigned is not None and permission_required_value is not None and ("ALL_ACCOUNTS" in permission_required_value or account_id in permission_required_value)):
                    log.info("Required keys found in the permission sets to add to groups and to new account")
                    groups_to_be_assigned=groups_to_be_assigned.split("/")
                    for grp in groups_to_be_assigned:
                        if(grp in permission_to_add_to_grps):
                            permission_to_add_to_grps[grp]+=f",{perm}"
                        else:
                            permission_to_add_to_grps[grp]=perm
                            
                else:
                    log.info(f"Key not found in permission set {perm}, skipping it")
            
            log.info(f"We now have list of all permissions that we need to assign to the account. Below is the list")
            log.info(permission_to_add_to_grps)
            
            
            for grp, perms in permission_to_add_to_grps.items():
                perms=perms.split(",")
                for perm in perms:
                    log.info(f"Adding the permission {perm} to group {grp} in account {account_id}")
                    addPermToGroupConfig(grp,perm,account_id)
        else:
            return sendResponse("failure",f"The create account status resulted in failure. Please reach out to CIAS Team.")
    except Exception as e:
        log.error(f"Something went wrong!! while onboarding a new account in IDC.Please reach out to CIAS Team. Here is the error message - {e}")
    return sendResponse("failure",f"The create account status resulted in failure. Please reach out to CIAS Team.")
    


def create_permssion(perm_arn):
    try:
        tag_perm = sso_client.list_tags_for_resource(
            InstanceArn=instance_arn,
            ResourceArn=perm_arn
        )
        permission_to_add_to_grps={}
        permission_required_value = next((tag['Value'] for tag in tag_perm.get('Tags', []) if tag.get('Key') == 'permission-required'), "")
        groups_to_be_assigned = next((tag['Value'] for tag in tag_perm.get('Tags', []) if tag.get('Key') == 'groups-to-add'), "")
        if(groups_to_be_assigned !="" and permission_required_value!=""):
            log.info("Required keys found in the permission sets to add to groups and to all accounts")
            groups_to_be_assigned=groups_to_be_assigned.split("/")
            for grp in groups_to_be_assigned:
                if(grp in permission_to_add_to_grps):
                    permission_to_add_to_grps[grp]+=f",{perm_arn}"
                else:
                    permission_to_add_to_grps[grp]=perm_arn
            print(permission_to_add_to_grps)
            acc_list=[]
            if(permission_required_value=="ALL_ACCOUNTS"):
                log.info(f"The permission {perm_arn} has to be added in all accounts. We have indentified that below groups need the access to the permission set")
                acc_list_response = org_client.list_accounts()
                acc_list_response=acc_list_response['Accounts']
                for acc in acc_list_response:
                    if(acc['Status']=="ACTIVE"):
                        acc_list.append(acc['Id'])
            else:
                acc_list=permission_required_value.split("/")
            for account_id in acc_list:
                for grp, perms in permission_to_add_to_grps.items():
                    perms=perms.split(",")
                    for perm in perms:
                        log.info(f"Adding the permission {perm} in acc {account_id} associated with group {grp}")
                        addPermToGroupConfig(grp,perm,account_id)
                        
        else:
            log.info(f"Key not found in permission set {perm_arn}, skipping it")
    except Exception as e:
        log.error(f"Something went wrong!! while updating the permission set with accounts.Please reach out to CIAS Team. Here is the error message - {e}")
    return sendResponse("failure",f"The create account status resulted in failure. Please reach out to CIAS Team.")
        
    
    

def lambda_handler(event, context):
    global global_context
    global_context = context
    event_data = event
    execution_context = vars(context)
    if("eventName" in str(event)):
        event_name = event.get("detail", {}).get("eventName", "")
        if(event_name=="DisableUser"):
            log.info(f"{event_name}: Here are the details {event['detail']['requestParameters']}")
            time.sleep(5)
            return delete_user_from_idc(event['detail']['requestParameters']['userId'])
        if(event_name=="CreateAccount"):
            log.info(f"{event_name} event triggered")
            return create_account(event['detail']['responseElements']['createAccountStatus']['id'])
        if(event_name=="CreatePermissionSet"):
            log.info("A new permission set has been created. Which means we need to add the policy to the desired accounts and groups")
            perm_arn=event['detail']['responseElements']['permissionSet']['permissionSetArn']
            log.info(f"{event_name}: Here are the details {perm_arn}")
            time.sleep(5)
            return create_permssion(perm_arn)
        if(event_name=="TagResource"):
            log.info("A permission set has been updated. Which means we need to add the policy to the desired accounts and groups")
            log.info("Note we will be just adding permissions to accounts and not removing it. If permissions and groups are to be removed, please delete the permission set and recreate a new one")
            perm_arn=event['detail']['requestParameters']['resourceArn']
            log.info(f"{event_name}: Here are the details {perm_arn}")
            time.sleep(5)
            return create_permssion(perm_arn)
            
    log.info(f"Function run - {event_data['rawPath']}\n\nQueries - {event_data['rawQueryString']}\n\nLog Group - {execution_context['log_group_name']}\n\nLog Stream - {execution_context['log_stream_name']}")
    return app.resolve(event, context)
