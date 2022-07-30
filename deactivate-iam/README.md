## deactivate-iam.py

## Description
This script deactivates iam users and access deys if they are not accessed for more than 90 days

### Cloudwatch Rule
* Execute Lambda function at 10AM everyday
* Cron: 
```0 10 * * ? *```

### Lambda Configuration
#### Lambda Role
* Create Inline policy for the lambda Role

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:DeleteLoginProfile",
                "iam:GetAccessKeyLastUsed",
                "iam:ListAccessKeys",
                "iam:ListUsers",
                "iam:GetUser",
                "iam:GetLoginProfile",
                "iam:UpdateAccessKey"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Timeout
* Set the timeout to 2 minutes