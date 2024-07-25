import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def enable_secret_rotation(secret_id, rotation_lambda_arn, rotation_days):
    try:
        secrets_manager = boto3.client('secretsmanager')
        rotation_rules = {"AutomaticallyAfterDays": int(rotation_days)}
        secrets_manager.rotate_secret(
            SecretId=secret_id,
            RotationLambdaARN=rotation_lambda_arn,
            RotationRules=rotation_rules
        )
        logger.info(f"Enabled rotation for secret: {secret_id}")

    except Exception as e:
        logger.error(f"Error enabling secret rotation: {e}")
        raise
