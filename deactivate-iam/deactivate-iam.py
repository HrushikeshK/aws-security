import json
import boto3
from datetime import datetime
from datetime import timedelta
from botocore.exceptions import ClientError
import requests
import os


date_now = datetime.now() #+ timedelta(days=90)
iam_client = boto3.client('iam')
iam_resource = boto3.resource('iam')
max_idle_days = 90
max_items = 50

url = os.environ['WEBHOOK_URL']
slack_channel = os.environ['SLACK_CHANNEL_NAME']
slack_emoji = ":aws-iam:"   # Make sure this emoji is already added in your workspace. Source: https://github.com/Surgo/aws_emojipacks
slack_bot_username = "IAM Audit Bot"  # Slackbot Username
slack_message_title = ""

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
    

def get_sensored_access_key(access_key):
    first_four = access_key[:4]
    last_four = access_key[-4:]
    return first_four + "*********" + last_four

def get_account_alias():
    aliases = iam_client.list_account_aliases()['AccountAliases']
    alias = ""
    if len(aliases) == 0:
        alias = id = boto3.client('sts').get_caller_identity().get('Account')
    else:
        alias = aliases[0]
    return alias
    
def get_slack_payload(user, is_access_key, access_key="", arn="", diff=-1):
    
    account_alias = get_account_alias()
    payload = ""
    if diff == -1:
        diff = "Never"
    else:
        diff = str(diff) + " days"
    if is_access_key:
        payload = """{
                 \n\t\"channel\": \"#""" + slack_channel + """\",
                 \n\t\"username\": \"""" + slack_bot_username + """\",
                 \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
                 \n\t\"attachments\":[\n
                                       {\n
                                         \"fallback\":\"Access Key Deactivated\",\n
                                         \"pretext\":\"Access Key Deactivated\",\n
                                         \"color\":\"#34bb13\",\n
                                         \"fields\":[\n
                                                     {\n
                                                       \"value\":\"*Account:* """ + account_alias + """\n*User:* """ + user + """\n*ARN:* """ + arn + """\n*Access Key:* """ + access_key + """\n*Last Accessed:* """ + diff + """ \"\n
                                                     }\n
                                                   ]\n
                                         }\n
                                      ]\n
             }"""
    else:
        payload = """{
                 \n\t\"channel\": \"#""" + slack_channel + """\",
                 \n\t\"username\": \"""" + slack_bot_username + """\",
                 \n\t\"icon_emoji\": \"""" + slack_emoji + """\",
                 \n\t\"attachments\":[\n
                                       {\n
                                         \"fallback\":\"User Deactivated\",\n
                                         \"pretext\":\"User Deactivated\",\n
                                         \"color\":\"#34bb13\",\n
                                         \"fields\":[\n
                                                     {\n
                                                       \"value\":\"*Account:* """ + account_alias + """\n*User:* """ + user + """\n*ARN:* """ + arn + """\n*Last Accessed:* """ + diff + """ \"\n
                                                     }\n
                                                   ]\n
                                         }\n
                                      ]\n
             }"""
    return payload


def lambda_handler(event, context):
    try:
        res_users = iam_client.list_users(
        MaxItems=max_items
        )
        for user in res_users['Users']:
            check_login_profile(user)
            check_access_keys(user)
    except ClientError as error:
        print('An error occurred while fetching user list.', error)
    
    if res_users['IsTruncated']:
        while res_users['IsTruncated']:
            marker = res_users['Marker']
            try:
                res_users = iam_client.list_users(Marker=marker,MaxItems=max_items)
                for user in res_users['Users']:
                    check_login_profile(user)
                    check_access_keys(user)
            except ClientError as error:
                print('An error occurred while fetching user list.', error)

def check_login_profile(userData):
    created_date = datetime.now()
    last_used_date = datetime.now()

    user_arn = userData['Arn']
    username = userData['UserName']
    user = iam_resource.User(username)
    login_profile = iam_resource.LoginProfile(username)
    user.load()

    passwd_last_used = user.password_last_used
    try:
        # Deactivate users with "None" PasswordLastUsed
        if passwd_last_used == None:
            ret_val = login_profile.delete()
            response = requests.request("POST", url, data=get_slack_payload(username, False, arn=user_arn), headers=headers)
        # Deactivate users with PasswordLastUsed more than 90 days
        else:
            last_used_date = passwd_last_used.replace(tzinfo=None)
            difference = date_now - last_used_date
            if difference.days > max_idle_days:
                # Delete user password
                ret_val = login_profile.delete()
                response = requests.request("POST", url, data=get_slack_payload(username, False, arn=user_arn, diff=difference.days), headers=headers)
                    
    except Exception as e:
        print("Exception occurred:", e)

def check_access_keys(userData):
    created_date = datetime.now()
    last_used_date = datetime.now()
    access_key_id = None

    username = userData['UserName']
    user_arn = userData['Arn']

     # Below we are checking for access keys last usage
    try:
        res_keys = iam_client.list_access_keys(UserName=username,MaxItems=2)

        if 'AccessKeyMetadata' in res_keys:
            for key in res_keys['AccessKeyMetadata']:
                if 'CreateDate' in key:
                    created_date = res_keys['AccessKeyMetadata'][0]['CreateDate'].replace(tzinfo=None)
                if 'AccessKeyId' in key:
                    access_key_id = key['AccessKeyId']
                    res_last_used_key = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    if 'LastUsedDate' in res_last_used_key['AccessKeyLastUsed']:
                        last_used_date = res_last_used_key['AccessKeyLastUsed']['LastUsedDate'].replace(tzinfo=None)
                    else:
                        last_used_date = created_date
                    
                difference = date_now - last_used_date
                access_key_status = key['Status']         # Get status of the access keys
                if difference.days > max_idle_days and access_key_status == "Active":
                    access_key = iam_resource.AccessKey(username, access_key_id)   # Get user's access key details
                       
                    # Deactivate Access key
                    ret_val = access_key.deactivate()
                    response = requests.request("POST", url, data=get_slack_payload(username, True, get_sensored_access_key(access_key_id), user_arn, diff=difference.days), headers=headers)
                        
    except ClientError as error:
        print('An error occurred while listing access keys', error)
