import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import traceback
from time import sleep
import json
import requests
import os
import time

LAST_ACCESS_THRESHOLD = 90
MAX_ITEMS = 50

# Slack details
url = os.environ['WEBHOOK_URL']
slack_channel = os.environ['SLACK_CHANNEL_NAME']
whitelist_tags = os.environ['WHITELIST_TAG']
slack_emoji = ":aws-iam:"   # Make sure this emoji is already added in your workspace. Source: https://github.com/Surgo/aws_emojipacks
slack_bot_username = "IAM Audit Bot"  # Slackbot Username
slack_message_title = "OverPrivileged Account detected"

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
    
def get_slack_payload(status_code, user, user_arn, policy_name):
  account_alias = get_account_alias()
  payload = ""
  if status_code == 1:
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
                                               \"value\":\"*Account:* """ + account_alias + """\n*User:* """ + user + """\n*ARN:* """ + user_arn + """\n*Attached Deny Policy Name:* """ + policy_name + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""
  
  elif status_code == 2:
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
                                               \"value\":\":x: Could not attach Deny Policy to the user :x:\n*Reason*: Cannot exceed quota for PoliciesPerUser: 10\n*Account:* """ + account_alias + """\n*User:* """ + user + """\n*ARN:* """ + user_arn + """\",\n
                                             }\n
                                           ]\n
                                 }\n
                              ]\n
  }"""   
  
  # Fix for Slack Rate limit
  time.sleep(2)
 
  return payload

def get_user_age(userData):
  time_now = datetime.now()
  created_date = userData['CreateDate'].replace(tzinfo=None)
  # Get creation days 
  difference = time_now - created_date

  return difference.days

# Get number of managed Policies attached to the user
def get_attached_policy_count(username):
  iam_client = get_iam_client()
  managed_user_policies = iam_client.list_attached_user_policies(UserName=username)
  deny_policy_name = 'explicitDenyExtraPrivilegesLambdaPolicy-' + username
  attached_policies = managed_user_policies['AttachedPolicies']
  policy_count = len(attached_policies)
  for policy in attached_policies:
    # This is to make sure we don't count our very own attached policy. Because that can be deleted and attached again after updating
      if policy['PolicyName'] == deny_policy_name:
          policy_count = policy_count - 1
  return policy_count

def is_user_whitelisted(username):
  iam_resource = boto3.resource('iam')
  iam_user = iam_resource.User(username)
  # If user has no tags, return False
  if iam_user.tags == None:
    return False
  whitelist_tag_list = whitelist_tags.split(',')
  for tag_pair in whitelist_tag_list:
    key = tag_pair.split(':')[0].strip()
    value = tag_pair.split(':')[1].strip()
    for tag in iam_user.tags:
      if tag["Key"] == key and tag["Value"].lower() == value.lower():
        return True
  return False


def get_older_iam_users(list_users_arn):
  client = get_iam_client()
  services_access = {}
  sts = boto3.client('sts')
  account_id = sts.get_caller_identity()['Account']
  
  if not list_users_arn:
    raise Exception("No users found in account")  
    
  for user in list_users_arn['Users']:
    username = user['UserName']
   
    user_arn = f'arn:aws:iam::{account_id}:user/{username}'
    
    # Check whitelisted users based on the tags given in WHITELIST_TAG env variable
    # Example of variable value: "key1:value1, key2:value2,key3:value3"
    if is_user_whitelisted(username):
      print("Ignoring user {}. The user is whitelisted".format(username))
    # If the user already has 10 policies attached, then we cannot attach any new policy. Ignore the user for the time being
    elif get_attached_policy_count(username) >= 10:
      print("Ignoring user {}. Cannot exceed quota for PoliciesPerUser: 10".format(username))
      slack_response = requests.request("POST", url, data=get_slack_payload(2, username, user_arn, "N/A"), headers=headers)
    # We consider the user that is created at least 90 days prior
    elif get_user_age(user) > 90:
      TODAYS_DAY = datetime.now(timezone.utc)
      ARNS = user['Arn']
    
      jobid_response = client.generate_service_last_accessed_details(Arn=ARNS)
    
      role_jobid = jobid_response['JobId']

      service_response = client.get_service_last_accessed_details(JobId=role_jobid)

    # checking if job is completed else wait and retry until job is completed
      while service_response['JobStatus'] != 'COMPLETED':
        service_response = client.get_service_last_accessed_details(JobId=role_jobid)
        sleep(1)
    
    # getting last access services
      last_accessed_services = service_response['ServicesLastAccessed']

      services_access[username] = {}
      for service in last_accessed_services:
        if service['TotalAuthenticatedEntities'] == 0:
          services_access[username][service['ServiceNamespace']] = -1
        else:
          try:
            role_lastaccess_day = service['LastAuthenticated']
          
          # difference between today and last access date        
            days_difference =  TODAYS_DAY - role_lastaccess_day
          
          # checking if difference is greater than 90
            check_difference = days_difference.days > LAST_ACCESS_THRESHOLD 
  
            if check_difference:
              services_access[username][service['ServiceNamespace']] = days_difference.days

          except Exception as e:
            print("Exception occured: ", e)
          #continue
    else:
      if get_user_age(user) == 0:
        print("Ignoring user {}. User was created within 24 hours".format(user['UserName']))
      else:
        print("Ignoring user {}. User was created {} days ago".format(user['UserName'], get_user_age(user)))
    
  return services_access
  

def is_policy_attached(username, policy_name):
  client = get_iam_client()
  
  response = client.list_attached_user_policies(UserName=username)['AttachedPolicies']
  
  for policy in response:
    if policy_name == policy['PolicyName']:
      return True
  return False


def create_policy_list(user_access_list):
  # Create the policy list
  for user,attr in user_access_list.items():
    count = 0
    policy_list = list()
    for svc, days in attr.items():
      policy_list.append(svc+":*")
    policy_name = "explicitDenyExtraPrivilegesLambdaPolicy-" + user 
    apply_explicit_deny_policy(user, policy_name, policy_list)


def apply_explicit_deny_policy(username, policy_name, policy_list):
    
    client = boto3.client('iam')
    sts = boto3.client('sts')
    iam = boto3.resource('iam')
    user = iam.User(username) 
    
    policy = {
    "Version": "2012-10-17"
    }
    statement = list()
 
    policy_exist = True
    account_id = sts.get_caller_identity()['Account']
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'
    try:
     # Check if policy exist Fast and direct
      _ = client.get_policy(PolicyArn=policy_arn)['Policy']
    except client.exceptions.NoSuchEntityException as error:
      print("Creating a new Explicit Deny Policy for user ", username)
      policy_exist = False
        
    # If there is no change in the policies to be added or the user has no permissions to begin with
    if len(policy_list) == 0:
      print("No change in DenyPolicy for user {}".format(username))
      
    # If the policy is already created and there is something to updated to the deny policy
    elif policy_exist and len(policy_list) > 0:
      old_policy = client.get_policy(PolicyArn=policy_arn)
      policy_version = client.get_policy_version(PolicyArn = policy_arn, VersionId = old_policy['Policy']['DefaultVersionId'])
      old_policy_list = policy_version['PolicyVersion']['Document']['Statement'][0]['Action']
        
      print("Updating Policy for user: ", username)
      
      # Make sure the policy is attached
      if is_policy_attached(username, policy_name):
      # Add the resources that are extra
        for i in old_policy_list:
          policy_list.append(i)
        policy_list.sort()
        response = user.detach_policy(PolicyArn=policy_arn)
      else:
        print("Re-attaching policy for user {}".format(username))
        
      response = client.delete_policy(PolicyArn=policy_arn) 
        
      statement.append({ "Action": policy_list, "Effect": "Deny", "Resource": "*" })
      policy['Statement'] = statement

        # convert into JSON:
      my_managed_policy = json.dumps(policy)
        
      # Create updated Deny Policy
      response = client.create_policy(PolicyName=policy_name,PolicyDocument=my_managed_policy)

      response = user.attach_policy(PolicyArn=policy_arn)
      
      user_arn = f'arn:aws:iam::{account_id}:user/{username}'
      slack_response = requests.request("POST", url, data=get_slack_payload(1,username, user_arn, policy_name), headers=headers)
        
    # Creating a new Explicit Deny Policy
    elif not policy_exist and len(policy_list) > 0:
      statement.append({ "Action": policy_list, "Effect": "Deny", "Resource": "*" })
      policy['Statement'] = statement
      
      # convert into JSON:
      my_managed_policy = json.dumps(policy)
        
      # Create updated Deny Policy
      response = client.create_policy(PolicyName=policy_name,PolicyDocument=my_managed_policy)
      response = user.attach_policy(PolicyArn=policy_arn)
      
      user_arn = f'arn:aws:iam::{account_id}:user/{username}'
      slack_response = requests.request("POST", url, data=get_slack_payload(1,username, user_arn, policy_name), headers=headers)
   

def lambda_handler(event, context):
  iam_client = get_iam_client()
  try:
    # Make sure you consider all IAM users
    try:
      res_users = iam_client.list_users(MaxItems=MAX_ITEMS)
      create_policy_list(get_older_iam_users(res_users))
    except ClientError as error:
      print('An error occurred while fetching user list.', error)
    
    if res_users['IsTruncated']:
      while res_users['IsTruncated']:
        marker = res_users['Marker']
        try:
          res_users = iam_client.list_users(Marker=marker,MaxItems=MAX_ITEMS)
          create_policy_list(get_older_iam_users(res_users))
        except ClientError as error:
          print('An error occurred while fetching user list.', error)
    
  except Exception as e:
    traceback.print_exc()
    raise Exception(str(e))