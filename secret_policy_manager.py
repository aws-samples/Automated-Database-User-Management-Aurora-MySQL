import json

def update_secret_policy_template(role_arns, account_id, new_secret_arn):
    policy_template = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{account_id}:root"
                },
                "Action": "secretsmanager:*",
                "Resource": new_secret_arn
            }
        ]
    }

    for role_arn in role_arns:
        role_statement = {
            "Effect": "Allow",
            "Principal": {
                "AWS": role_arn
            },
            "Action": "secretsmanager:GetSecretValue",
            "Resource": new_secret_arn
        }
        policy_template['Statement'].append(role_statement)

    return json.dumps(policy_template)
