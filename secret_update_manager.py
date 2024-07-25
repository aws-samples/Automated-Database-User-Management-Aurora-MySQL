import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def update_secret_policy(secret_id, policy):
    try:
        secrets_manager = boto3.client('secretsmanager')
        secrets_manager.put_resource_policy(SecretId=secret_id, ResourcePolicy=policy)
        logger.info(f"Updated resource policy for secret: {secret_id}")

    except Exception as e:
        logger.error(f"Error updating secret policy: {e}")
        raise

def update_secret_rotation(secret_id, rotation_lambda_arn, rotation_days):
    try:
        secrets_manager = boto3.client('secretsmanager')
        rotation_rules = {"AutomaticallyAfterDays": rotation_days}

        secrets_manager.rotate_secret(
            SecretId=secret_id,
            RotationLambdaARN=rotation_lambda_arn,
            RotationRules=rotation_rules
        )
        logger.info(f"Updated rotation schedule for secret: {secret_id}")

    except Exception as e:
        logger.error(f"Error updating secret rotation: {e}")
        raise
