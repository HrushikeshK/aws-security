import json
import boto3
from urllib import request
import os
import time

slack_webhook = os.environ['SLACK_WEBHOOK']

ec2_resource = boto3.resource('ec2')
f_handler = open("failed-instances.txt", "a")
bf_handler = open("blacklisted-instances.txt","a")

def listInstances():
    instances = ec2_resource.instances.all()

    # for instance in instances:
    #     print(f'EC2 instance {instance.id}" information:')
    #     print(f'Instance state: {instance.state["Name"]}')
    #     print(f'Instance AMI: {instance.image.id}')
    #     print(f'Instance platform: {instance.platform}')
    #     print(f'Instance type: "{instance.instance_type}')
    #     print(f'Piblic IPv4 address: {instance.public_ip_address}')
    #     print('-'*60)

    return instances
        
def describeInstance(instance_id):
    client = boto3.client('ec2')
    response = client.describe_instances(
        InstanceIds=[instance_id]
    )
    return response
    
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
    
def send_message_to_slack(text):
    post = {"text": "{0}".format(text)}
    try:
        json_data = json.dumps(post)
        req = request.Request(slack_webhook,
                              data=json_data.encode('ascii'),
                              headers={'Content-Type': 'application/json'})
        resp = request.urlopen(req)
    except Exception as em:
        print("Failed to send message to slack")
        print("EXCEPTION: " + str(em))
        
def getPolicyAttached(role):
    client = boto3.client('iam')
    response = client.list_attached_role_policies(
        RoleName=role
    )
    return response
    
    
def attachPolicy(role):
    policy_arns_to_attach_to_role = ['arn:aws:iam::aws:policy/AmazonSSMFullAccess','arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore']
    client = boto3.client('iam')
    try:
        for arn in policy_arns_to_attach_to_role:
            response = client.attach_role_policy(
                RoleName=role,
                PolicyArn=arn
            )
            print("Attached policy: ", arn.split("/")[-1])
        return "All policy attached"
    except:
        return "Cannot attach some or all policy"

def configure(count, instance_id, account_id):
    
    counter = count
    instance_id = instance_id
    time.sleep(60)
    client = boto3.client('ssm')
    try:
        print("Sending command...")
        response = client.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            TimeoutSeconds=600,
            Parameters={
                'commands': [
                    '#!/bin/bash',
                    'echo "Checking OS..."',
                    'cat /etc/os-release | grep "PRETTY_NAME" | grep "Ubuntu" > /dev/null',
                    'res1=`echo $?`',
                    'if [ $res1 == 0 ]',
                    'then',
                        '## Ubuntu ##',
                        'echo "Installing on Ubuntu"',
                        'res_str=`grep "^PRETTY_NAME" /etc/os-release`',
                        'if ! [ $(systemctl is-active traps_pmd.service) == "active" ]; then',
                            'curl -so cortex-agent.deb <endpoint>',
                            'sudo apt install ./cortex-agent.deb',
                            'systemctl is-active --quiet traps_pmd.service && echo "Cortex XDR was installed, started the service."',
                        'else',
                            'echo "Cortex XDR installed already on instance $ID"',
                        'fi',
                    'fi',
                    'cat /etc/os-release | grep "PRETTY_NAME" | grep "Amazon Linux" > /dev/null',
                    'res2=`echo $?`',
                    'if [ $res2 == 0 ]; then',
                        '## Amazon Linux',
                        'echo "Installing on Amazon Linux."',
                        'if ! [ $(systemctl is-active traps_pmd.service) == "active" ]; then',           
                            'sudo yum install -y <endpoint>',       
                            'systemctl is-active --quiet traps_pmd.service && echo "Cortex XDR was installed, started the service."',
                        'else',
                            'echo "Cortex XDR installed already on instance $ID"',
                        'fi',
                    'fi',
                ]
            },
            CloudWatchOutputConfig={
                'CloudWatchLogGroupName': 'cortex-agent-install-running-instances-logs',
                'CloudWatchOutputEnabled': True
            }
        )
        print("Command Sent Response: {}".format(response))
    except Exception as e:
        account_alias = get_account_alias()
        if counter < 5:
            counter += 1
            print("Repeat counter: ", counter)
            msg = "Failed to install cortex agent on: *" + instance_id + " " + account_alias + "*\r\n" + str(e) + "\r\n" + "Trying again["+str(counter)+"] in 60 seconds..."
            send_message_to_slack(msg)
            print("Sending document:- ", configure)
            configure(counter, instance_id, account_id)
            print("Sent on " + str(counter) + "attempt")
        else:
            print("Not able to send document to instance")
            msg = "Failed to install cortex agent on: *" + instance_id + " " + account_alias + "*\r\n" + str(e) + "\r\n" + "Please configure required configurations for cortex manually."
            send_message_to_slack(msg)
            f_handler.write(instance_id+"\n")
            # return 1

def configure_windows(count, instance_id, account_id):
    counter = count
    instance_id = instance_id
    time.sleep(60)
    client = boto3.client('ssm')
    try:
        print("Sending command...")
        response = client.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunPowerShellScript',
            TimeoutSeconds=600,
            Parameters={
                'commands': [

                    'Invoke-WebRequest -Uri <endpoint> -OutFile ${env:tmp}\cortex-agent.msi; msiexec.exe /i ${env:tmp}\cortex-agent.msi /q',
                ]
            },
            CloudWatchOutputConfig={
                'CloudWatchLogGroupName': 'cortex-agent-install-running-instances-logs',
                'CloudWatchOutputEnabled': True
            }
        )
        print("Command Sent Response: {}".format(response))
    except Exception as e:
        account_alias = get_account_alias()
        if counter < 5:
            counter += 1
            print("Repeat counter: ", counter)
            msg = "Failed to install cortex agent on: *" + instance_id + " " + account_alias + "*\r\n" + str(e) + "\r\n" + "Trying again["+str(counter)+"] in 60 seconds..."
            send_message_to_slack(msg)
            print("Sending document:- ", configure_windows)
            configure_windows(counter, instance_id, account_id)
            print("Sent on " + str(counter) + "attempt")
        else:
            print("Not able to send document to instance")
            msg = "Failed to install cortex agent on: *" + instance_id + " " + account_alias + "*\r\n" + str(e) + "\r\n" + "Please configure required configurations for cortex manually."
            send_message_to_slack(msg)
            f_handler.write(instance_id+"\n")

def setup_windows_ssm(instance_id, response):
    sts = boto3.client('sts')
    client = boto3.client('ec2')
    my_session = boto3.session.Session()
    my_region = my_session.region_name

    account_alias = get_account_alias()
    account_id = sts.get_caller_identity()['Account']
    to_attach_role_arn = f'arn:aws:iam::{account_id}:instance-profile/ec2-ssm'
    to_attach_role_name = "ec2-ssm"
    try:
        iam = response['Reservations'][0]['Instances'][0]['IamInstanceProfile']['Arn'].split("/")[-1]
        print("IAM Role: ", iam)
        try:
            resp = getPolicyAttached(iam)
            total_policies = len(resp['AttachedPolicies'])
            print("Total attached policy: ", total_policies)
            policy_list = []
            for policy in resp['AttachedPolicies']:
                policy_list.append(policy['PolicyName'])
            print("Policies: ", policy_list)
            if "AdministratorAccess" in policy_list:
                print("No need to attach any policy for SSM")
                configure_windows(1, instance_id, account_id)
                print("Send document via ssm successfully")
            elif ("AmazonS3ReadOnlyAccess" in policy_list or "AmazonS3FullAccess" in policy_list) and ("AmazonSSMFullAccess" in policy_list):
                print("No need to attach any policy")
                configure_windows(1, instance_id, account_id)
                print("Send document via ssm successfully")
            else:
                if total_policies < 10:
                    print("Attaching policy to role...")
                    resp = attachPolicy(iam)
                    print(resp)
                    if resp == "All policy attached":
                        configure_windows(1, instance_id, account_id)
                        print("Send document via ssm successfully")
                    else:
                        msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nSome or all required policy not able to attach\r\nTry to attach all policy and configure required things for Cortex agent installation"
                        print("Message: ", msg)
                        send_message_to_slack(msg)
                        f_handler.write(instance_id+"\n")
                else:
                    msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nMaximum number of policy already attached\nTry to replace required policy and configure required things for Cortex agent installation"
                    print("Message: ", msg)
                    send_message_to_slack(msg)
                    f_handler.write(instance_id+"\n")
        except Exception as e:
            print("Exception: ", str(e))
            msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nSome internal error ocurred.\r\nNot able to Install Cortex agent.Please check"
            send_message_to_slack(msg)
            f_handler.write(instance_id+"\n")
    except Exception as e:
        print("No IAM role found")
        try:
            resp = client.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': to_attach_role_arn,
                    'Name': to_attach_role_name
                },
                InstanceId=instance_id
            )
            print("Attached role to Windows instance: ", instance_id)
            try:
                configure_windows(1, instance_id, account_id)
            except Exception as e:
                msg = "*" + account_alias + "* \n" + "Failed to configure Cortex installation on: *" + instance_id + "*\r\n" + str(e) + "\r\n" + "Please configure required configurations for the agent manually."
                send_message_to_slack(msg)
                f_handler.write(instance_id+"\n")
        except Exception as e:
            print("Failed to attach role to instance: "+ instance_id+ "\r\n"+ str(e))
            msg = "*" + account_alias + "*\r\n*InstanceId:*"+instance_id+"\r\nFailed to attach role\r\nTry to attach and configure required things for Cortex agent manually"
            send_message_to_slack(msg)
            f_handler.write(instance_id+"\n")


############ ENTRYPOINT ####################
def lambda_handler():

    sts = boto3.client('sts')
    client = boto3.client('ec2')
    my_session = boto3.session.Session()
    my_region = my_session.region_name
    # Causing memory issue in Global Prod
    instance_blacklist = ["t3.nano", "t3.micro", "t3.small", "t3a.nano", "t3a.micro", "t3a.small"]

    counter = 1
    instance_count = len(list(listInstances()))
    
    for instance in listInstances():
        print("="*10 + " New Instance " + "="*10)
        print("Progress: {}/{}".format(counter,instance_count))
        counter += 1
        if instance.state["Name"] == 'running':
            instance_id = instance.id      
            account_alias = get_account_alias()
            account_id = sts.get_caller_identity()['Account']
            to_attach_role_arn = f'arn:aws:iam::{account_id}:instance-profile/ec2-ssm'
            to_attach_role_name = "ec2-ssm"

            response = describeInstance(instance_id)
            print(response)
            instance_type = ""
            try:
                instance_type = response['Reservations'][0]['Instances'][0]['InstanceType']
                print("Instance {} has Instance Type: {}".format(instance_id, instance_type))
            except:
                instance_type = "other"
                msg = "Instance {} with no instance type {}. Moving forward".format(instance_id, instance_type)
                send_message_to_slack(msg)

            if instance_type in instance_blacklist:
                msg = "Ignoring instance {}. Instance type is {}. Blacklisted!".format(instance_id, instance_type)
                send_message_to_slack(msg)
                bf_handler.write("{},{}\n".format(instance_id,instance_type))
            else: 
                try:
                    platform = response['Reservations'][0]['Instances'][0]['Platform']

                    if platform == "windows":
                        print("Windows instance")
                        msg = "Installing Cortex agent for *Microsoft Windows*... \n*Instance:* {}\n*Region:* {}\n*Account:* {}".format(instance_id, my_region, account_alias)
                        send_message_to_slack(msg)
                        setup_windows_ssm(instance_id, response)
                    else:
                        print(platform, "instance")
                        print("Skipping the required configuration for Cortex \n*Instance:* {}\n*Region:* {}\n*Account:* {}".format(instance_id, my_region, account_alias))
                        msg = "Skipping the required configuration for Cortex agent \n*Instance:* {}\n*Region:* {}\n*Account:* {}".format(instance_id, my_region, account_alias)
                        send_message_to_slack(msg)
                        f_handler.write(instance_id+"\n")
                except Exception as e:
                    print("Linux instance.")
                    msg = "Preparing for the required configuration for installing the Cortex agent...\n*Instance:* {}\n*Region:* {}\n*Account:* {}".format(instance_id, my_region, account_alias)
                    send_message_to_slack(msg)
                    try:
                        iam = response['Reservations'][0]['Instances'][0]['IamInstanceProfile']['Arn'].split("/")[-1]
                        print("IAM Role: ", iam)
                        try:
                            resp = getPolicyAttached(iam)
                            total_policies = len(resp['AttachedPolicies'])
                            print("Total attached policy: ", total_policies)
                            policy_list = []
                            for policy in resp['AttachedPolicies']:
                                policy_list.append(policy['PolicyName'])
                            print("Policies: ", policy_list)
                            if "AdministratorAccess" in policy_list:
                                print("No need to attach any policy for SSM")
                                configure(1, instance_id, account_id)
                                print("Send document via ssm successfully")
                            elif ("AmazonS3ReadOnlyAccess" in policy_list or "AmazonS3FullAccess" in policy_list) and ("AmazonSSMFullAccess" in policy_list):
                                print("No need to attach any policy")
                                configure(1, instance_id, account_id)
                                print("Send document via ssm successfully")
                            else:
                                if total_policies < 10:
                                    print("Attaching policy to role...")
                                    resp = attachPolicy(iam)
                                    print(resp)
                                    if resp == "All policy attached":
                                        configure(1, instance_id, account_id)
                                        print("Send document via ssm successfully")
                                    else:
                                        msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nSome or all required policy not able to attach\r\nTry to attach all policy and configure required things for Cortex agent installation"
                                        print("Message: ", msg)
                                        send_message_to_slack(msg)
                                        f_handler.write(instance_id+"\n")
                                else:
                                    msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nMaximum number of policy already attached\nTry to replace required policy and configure required things for Cortex agent installation"
                                    print("Message: ", msg)
                                    send_message_to_slack(msg)
                                    f_handler.write(instance_id+"\n")
                        except Exception as e:
                            print("Exception: ", str(e))
                            msg = "*" + account_alias + "*\r\n*InstanceId:* "+instance_id+"\r\nSome internal error ocurred.\r\nNot able to Install Cortex agent.Please check"
                            send_message_to_slack(msg)
                            f_handler.write(instance_id+"\n")
                    except Exception as e:
                        print("No IAM role found")
                        try:
                            resp = client.associate_iam_instance_profile(
                                IamInstanceProfile={
                                    'Arn': to_attach_role_arn,
                                    'Name': to_attach_role_name
                                },
                                InstanceId=instance_id
                            )
                            print("Attached role to instance: {} and Platform {}".format(instance_id, platform))
                            try:
                                configure(1, instance_id, account_id)
                            except Exception as e:
                                msg = "*" + account_alias + "* \n" + "Failed to configure Cortex installation on: *" + instance_id + "*\r\n" + str(e) + "\r\n" + "Please configure required configurations for the agent manually."
                                send_message_to_slack(msg)
                                f_handler.write(instance_id+"\n")
                        except Exception as e:
                            print("Failed to attach role to instance: "+ instance_id+ "\r\n"+ str(e))
                            msg = "*" + account_alias + "*\r\n*InstanceId:*"+instance_id+"\r\nFailed to attach role\r\nTry to attach and configure required things for Cortex agent manually"
                            send_message_to_slack(msg)
                            f_handler.write(instance_id+"\n")
        else:
            print("Instance: {} is not running. Skipped!".format(instance.id))
            msg = "Instance: {} is not running. Skipped!".format(instance.id)
            send_message_to_slack(msg)


def main():
    lambda_handler()
    f_handler.close()
    bf_handler.close()

if __name__ == '__main__':
    main()