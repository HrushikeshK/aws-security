import json
import boto3
import requests
import os

# Slack details
url = os.environ['WEBHOOK_URL']
slack_channel = os.environ['SLACK_CHANNEL_NAME']
slack_bot_username = "AWS Audit Bot"  # Slackbot Username
my_session = boto3.session.Session()


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


def get_iam_client():
  """
  Get identity and access management client
  """
  return boto3.client(
    'iam'
  )

def get_account_alias():
  aliases = get_iam_client().list_account_aliases()['AccountAliases']
  alias = ""
  if len(aliases) == 0:
      alias = id = boto3.client('sts').get_caller_identity().get('Account')
  else:
    alias = aliases[0]
  return alias

def get_slack_payload_iam(operation_code, data):
  slack_emoji = ":aws-iam:"
  slack_message_title = data['title']    # Define it in the if statement depending on the activity
  payload = ""
  account_alias = get_account_alias()

  if operation_code == 1:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*User:* """ + data['username'] + """\n*Created By:* """ + data['created_by'] + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 2:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*User:* """ + data['username'] + """\n*Deleted By:* """ + data['deleted_by'] + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 3:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Role Name:* """ + data['role_name'] + """\n*Created By:* """ + data['created_by'] +  """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 4:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Role Name:* """ + data['role_name'] + """\n*Deleted By:* """ + data['deleted_by'] +  """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 5:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Policy Name:* """ + data['managed_policy'] + """\n*Attached to Role:* """ + data['attached_to'] +  """\n*Attached By:* """ + data['attached_by'] +  """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 6:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Policy Name:* """ + data['inline_policy'] + """\n*Attached to Role:* """ + data['attached_to'] +  """\n*Attached By:* """ + data['attached_by'] + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 7:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Policy Name:* """ + data['managed_policy'] + """\n*Detached From:* """ + data['detached_from'] +  """\n*Detached By: """ + data['detached_by'] + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 8:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Policy Name:* """ + data['inline_policy'] + """\n*Deleted From:* """ + data['deleted_from'] +  """\n*Deleted By:* """ + data['deleted_by'] + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""

 
  return payload
    
    

def get_slack_payload_ec2(operation_code, data):
  slack_emoji = ":aws-ec2:"
  slack_message_title = data['title']    # Define it in the if statement depending on the activity
  current_region = data['region']
  payload = ""
  account_alias = get_account_alias()[0]
  if operation_code == 1:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Security Group:* """ + data['sg_name'] + """\n*Security Group ID:* """ + data['sg_id'] + """\n*Created By:* """ + data['created_by'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 2:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Security Group ID:* """ + data['sg_id'] + """\n*Deleted By:* """ + data['deleted_by'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 3:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Security Group ID:* """ + data['sg_id'] +  """\n*Modified By:* """ + data['modified_by'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 4:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Created By:* """ + data['created_by'] + """\n*VPC ID:* """ + data['vpc_id'] + """\n*NACL ID:* """ + data['nacl_id'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 5:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Created By:* """ + data['created_by'] + """\n*NACL ID:* """ + data['nacl_id'] + """\n*Rule Number:* """ + data['rule_number'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 6:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Updated By:* """ + data['updated_by'] + """\n*NACL ID:* """ + data['nacl_id'] + """\n*Rule Number:* """ + data['rule_number'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 7:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Deleted By:* """ + data['deleted_by'] + """\n*NACL ID:* """ + data['nacl_id'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  elif operation_code == 8:
    payload = """{
          \n\t\"channel\": \"#""" + slack_channel + """\",
          \n\t\"username\": \"""" + slack_bot_username + """\",
          \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
          \n\t\"attachments\":[\n
                               {\n
                                 \"fallback\":\"""" + slack_message_title + """\",\n
                                 \"pretext\":\"""" + slack_message_title + """\",\n
                                 \"color\":\"#34bb13\",\n
                                 \"fields\":[\n
                                             {\n
                                               \"value\":\"*Account:* """ + account_alias + """\n*Deleted By:* """ + data['deleted_by'] + """\n*NACL ID:* """ + data['nacl_id'] + """\n*Rule Number:* """ + data['rule_number'] + """\n*Region:* """ + current_region + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  
  return payload

def lambda_handler(event, context):
    print("Event: ", event)
    
    eventSource = event['source']
    
    if eventSource == "aws.iam":
        handle_iam_events(event)
    elif eventSource == "aws.ec2":
        handle_ec2_events(event)
    
        
def handle_iam_events(event):
    eventName = event["detail"]["eventName"]
    
    if eventName == "CreateUser":
        slack_data = dict()
        slack_data['title'] = "New IAM User Created"
        print(slack_data['title'])
        slack_data['created_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['username'] = event["detail"]["requestParameters"]["userName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(1, slack_data), headers=headers)
        
    elif eventName == "DeleteUser":
        slack_data = dict()
        slack_data['title'] = "IAM User Deleted"
        print(slack_data['title'])
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['username'] = event["detail"]["requestParameters"]["userName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(2, slack_data), headers=headers)
        
    elif eventName == "CreateRole":
        slack_data = dict()
        slack_data['title'] = "New IAM Role Created"
        print(slack_data['title'])
        slack_data['created_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['role_name'] = event["detail"]["requestParameters"]["roleName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(3, slack_data), headers=headers)
        
    elif eventName == "DeleteRole":
        slack_data = dict()
        slack_data['title'] = "IAM Role Deleted"
        print(slack_data['title'])
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['role_name'] = event["detail"]["requestParameters"]["roleName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(4, slack_data), headers=headers)
        
    elif eventName == "AttachRolePolicy":
        slack_data = dict()
        slack_data['title'] = "Managed Policy attached to an IAM Role"
        print(slack_data['title'])
        slack_data['attached_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['managed_policy'] = event["detail"]["requestParameters"]["policyArn"]
        slack_data['attached_to'] = event["detail"]["requestParameters"]["roleName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(5, slack_data), headers=headers)
        
    elif eventName == "PutRolePolicy":
        slack_data = dict()
        slack_data['title'] = "Inline Policy attached to a IAM Role"
        print(slack_data['title'])
        slack_data['attached_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['inline_policy'] = event["detail"]["requestParameters"]["policyName"]
        slack_data['attached_to'] = event["detail"]["requestParameters"]["roleName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(6, slack_data), headers=headers)
        
    elif eventName == "DetachRolePolicy":
        slack_data = dict()
        slack_data['title'] = "Managed Policy detached from am IAM Role"
        slack_data['detached_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['managed_policy'] = event["detail"]["requestParameters"]["policyArn"]
        slack_data['detached_from'] = event["detail"]["requestParameters"]["roleName"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(7, slack_data), headers=headers)
        
    elif eventName == "DeleteRolePolicy":
        slack_data = dict()
        slack_data['title'] = "Inline Policy deleted from an IAM Role"
        slack_data['inline_policy'] = event["detail"]["requestParameters"]["policyName"]
        slack_data['deleted_from'] = event["detail"]["requestParameters"]["roleName"]
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_response = requests.request("POST", url, data=get_slack_payload_iam(8, slack_data), headers=headers)



def handle_ec2_events(event):
    slack_data = dict()
    
    eventName = event["detail"]["eventName"]
    slack_data['region'] = event["detail"]["awsRegion"]
    
    if eventName == "CreateSecurityGroup":
        slack_data['title'] = "New Security Group Created"
        print(slack_data['title'])
        slack_data['created_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['sg_id'] = event['detail']['responseElements']['groupId']
        slack_data['sg_name'] = event['detail']['requestParameters']['groupName']
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(1, slack_data), headers=headers)
        
    elif eventName == "DeleteSecurityGroup":
        slack_data['title'] = "Security Group Deleted"
        print(slack_data['title'])
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['sg_id'] = event['detail']['requestParameters']['groupId']
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(2, slack_data), headers=headers)
        
    elif eventName == "ModifySecurityGroupRules":
        slack_data['title'] = "Security Group Modified"
        print(slack_data['title'])
        slack_data['modified_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['sg_id'] = event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['GroupId']
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(3, slack_data), headers=headers)
    
    elif eventName == "CreateNetworkAcl":
        slack_data['title'] = "Network ACL created"
        print(slack_data['title'])
        slack_data['created_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['vpc_id'] = event['detail']['requestParameters']['vpcId']
        slack_data['nacl_id'] = event['detail']['responseElements']['networkAcl']['networkAclId']
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(4, slack_data), headers=headers)
        
    elif eventName == "CreateNetworkAclEntry":
        slack_data['title'] = "Network ACL Entry Created"
        print(slack_data['title'])
        slack_data['created_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['nacl_id'] = event['detail']['requestParameters']['networkAclId']
        slack_data['rule_number'] = str(event['detail']['requestParameters']['ruleNumber'])
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(5, slack_data), headers=headers)

    elif eventName == "ReplaceNetworkAclEntry":
        slack_data['title'] = "Netwrk ACL Entry Updated"
        print(slack_data['title'])
        slack_data['updated_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['nacl_id'] = event['detail']['requestParameters']['networkAclId']
        slack_data['rule_number'] = str(event['detail']['requestParameters']['ruleNumber'])
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(6, slack_data), headers=headers)
        
    elif eventName == "DeleteNetworkAcl":
        slack_data['title'] = "Network ACL deleted"
        print(slack_data['title'])
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['nacl_id'] = event['detail']['requestParameters']['networkAclId']
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(7, slack_data), headers=headers)
        
    elif eventName == "DeleteNetworkAclEntry":
        slack_data['title'] = "Network ACL entry deleted"
        print(slack_data['title'])
        slack_data['deleted_by'] = event["detail"]["userIdentity"]["arn"]
        slack_data['nacl_id'] = event['detail']['requestParameters']['networkAclId']
        slack_data['rule_number'] = str(event['detail']['requestParameters']['ruleNumber'])
        slack_response = requests.request("POST", url, data=get_slack_payload_ec2(8, slack_data), headers=headers)