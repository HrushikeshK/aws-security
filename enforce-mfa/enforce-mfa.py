import json
import boto3
import os, math
import requests
import datetime, time
from botocore.exceptions import ClientError

policyJson = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowViewAccountInfo",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:ListVirtualMFADevices"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowManageOwnPasswords",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:GetUser"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnAccessKeys",
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:ListAccessKeys",
                "iam:UpdateAccessKey"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnSigningCertificates",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteSigningCertificate",
                "iam:ListSigningCertificates",
                "iam:UpdateSigningCertificate",
                "iam:UploadSigningCertificate"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnSSHPublicKeys",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteSSHPublicKey",
                "iam:GetSSHPublicKey",
                "iam:ListSSHPublicKeys",
                "iam:UpdateSSHPublicKey",
                "iam:UploadSSHPublicKey"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnGitCredentials",
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceSpecificCredential",
                "iam:DeleteServiceSpecificCredential",
                "iam:ListServiceSpecificCredentials",
                "iam:ResetServiceSpecificCredential",
                "iam:UpdateServiceSpecificCredential"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnVirtualMFADevice",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice"
            ],
            "Resource": "arn:aws:iam::*:mfa/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnUserMFA",
            "Effect": "Allow",
            "Action": [
                "iam:DeactivateMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ResyncMFADevice"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "DenyAllExceptListedIfNoMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:ChangePassword",
                "iam:CreateLoginProfile",
                "sts:GetSessionToken"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}

headers = {
    'Content-Type': "application/json",
    'User-Agent': "PostmanRuntime/7.19.0",
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Postman-Token': "56df98df-XXXX-XXXX-XXXX-9a2k5q56b8gf,458sadwa-XXXX-XXXX-XXXX-p456z4564a45",
    'Host': "hooks.slack.com",
    'Accept-Encoding': "gzip, deflate",
    'Content-Length': "497",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
    }


client = boto3.client('iam')
sns = boto3.client('sns')
sts = boto3.client('sts')
iam_resource = boto3.resource('iam')
paginator = client.get_paginator('list_account_aliases')
whitelist_tags = os.environ['WHITELIST_TAG']
response = client.list_users()
url = os.environ['WEBHOOK_URL']
MFA_POLICY_NAME = "ForceMFA"
slack_emoji = ":aws-iam:" 



# Get number of managed Policies attached to the user
def get_attached_policy_count(username):
 # iam_client = get_iam_client()
  managed_user_policies = client.list_attached_user_policies(UserName=username)
  deny_policy_name = 'ForceMFA'
  attached_policies = managed_user_policies['AttachedPolicies']
  policy_count = len(attached_policies)
  for policy in attached_policies:
    # This is to make sure we don't count our very own attached policy. Because that can be deleted and attached again after updating
      if policy['PolicyName'] == deny_policy_name:
          policy_count = policy_count - 1
  return policy_count


def lambda_handler(event,context):
    # Check if the policy exist in this account. If not create one.
    if not is_policy_exist(MFA_POLICY_NAME):
        policyStr = json.dumps(policyJson)
        client.create_policy(PolicyName=MFA_POLICY_NAME,PolicyDocument=policyStr,Description="Policy Creation from Lambda function - Enforcing MFA")

    for user in response['Users']:
        username = user['UserName']
        userPolicyList = client.list_attached_user_policies(UserName=username)
        account_id = sts.get_caller_identity()['Account']
        
        if get_attached_policy_count(username) == 10:
            slack_response = requests.request("POST", url, data=send_slack_notification(2,username,account_id), headers=headers)
            
        elif not is_user_whitelisted(username) and not is_policy_attached(username,userPolicyList) and not is_mfa_enabled(username):
            
            policy_arn = f'arn:aws:iam::{account_id}:policy/{MFA_POLICY_NAME}'
            response2 = client.attach_user_policy(PolicyArn=policy_arn,UserName=username)
            print("Attaching ForceMFA policy to the user {}".format(username))
            slack_response = requests.request("POST", url, data=send_slack_notification(1,username,account_id), headers=headers)
        
            
def is_user_whitelisted(username):
    iam_user = iam_resource.User(username)
   # key = 'userType'
   # value = 'Service'
  # If user has no tags, return False
    print("is_user_whitelisted",iam_user.tags)
    if iam_user.tags == None:
        return False
    whitelist_tag_list = whitelist_tags.split(',')
    for tag_pair in whitelist_tag_list:
        key = tag_pair.split(':')[0].strip()
        value = tag_pair.split(':')[1].strip()
        print(key, value)
        for tag in iam_user.tags:
            if tag["Key"] == key and tag["Value"].lower() == value.lower():
                print("Ignoring user {}. Whitelisted using Tag".format(username))
                return True
    return False


def is_mfa_enabled(username):
    userMfa = client.list_mfa_devices(UserName=username)
    print("UserName " + username, userMfa)
    if len(userMfa['MFADevices']) == 0:
        return False 
    else:
        print("Ignoring user {}. MFA is already enabled".format(username))
        return True 

def is_policy_exist(policy_name):
    policy_exist = True
    account_id = sts.get_caller_identity()['Account']
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    try:
     # Check if policy exist Fast and direct
      _ = client.get_policy(PolicyArn=policy_arn)['Policy']
    except client.exceptions.NoSuchEntityException as error:
      print("Creating a new ForceMFA Policy")
      policy_exist = False
    return policy_exist
         
def get_account_alias():
    aliases = client.list_account_aliases()['AccountAliases']
    alias = ""
    if len(aliases) == 0:
        alias = id = boto3.client('sts').get_caller_identity().get('Account')
    else:
        alias = aliases[0]
    return alias

def is_policy_attached(user,userPolicyList):
    polList = []
    userPolicies = userPolicyList['AttachedPolicies']
    print("is Policy Attached for + " + user, userPolicies)
    
    for policy in userPolicies:
        if policy['PolicyName'] == MFA_POLICY_NAME:
            print("Ignoring user {}. MFA Policy already exist".format(user))
            return True
    return False
    

def send_slack_notification(status_code,user,account_id):
    account_alias = get_account_alias()
    payload = ""
    if status_code == 1:
        payload = """{
              \n\t\"channel\": \"aws-custom-alerts\",
              \n\t\"username\": \"Enforce MFA\",
              \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
              \n\t\"attachments\":[\n
                                   {\n
                                     \"fallback\":\"MFA Enabled\",\n
                                     \"pretext\":\"MFA Enabled\",\n
                                     \"color\":\"#34bb13\",\n
                                     \"fields\":[\n
                                                 {\n
                                                   \"value\":\"*User:* """ + user + """\n*AccountId:* """ + account_id + """\n*Account Alias:* """ + account_alias + """ \"\n
                                                 }\n
                                               ]\n
                                     }\n
                                  ]\n
        }"""
    elif status_code == 2:
        payload = """{
              \n\t\"channel\": \"aws-custom-alerts\",
              \n\t\"username\": \"Enforce MFA\",
              \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
              \n\t\"attachments\":[\n
                                   {\n
                                     \"fallback\":\"MFA Enabled\",\n
                                     \"pretext\":\"MFA Enabled\",\n
                                     \"color\":\"#34bb13\",\n
                                     \"fields\":[\n
                                                 {\n
                                                   \"value\":\":x: Could not attach ForceMFA Policy to the user :x:\n*Reason*: Cannot exceed quota for PoliciesPerUser: 10\n*Account:* """ + account_alias + """\n*User:* """ + user + """\n*AccountId:* """ + account_id + """\",\n
                                                }\n
                                               ]\n
                                     }\n
                                  ]\n
        }"""
    time.sleep(3) # To avoid slack api rate limit.
    return payload