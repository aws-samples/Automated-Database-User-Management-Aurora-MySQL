import json
import string
import boto3
import pymysql
import logging
import datetime
import os
from botocore.exceptions import ClientError
from secret_policy_manager import update_secret_policy_template
from secret_rotation_manager import enable_secret_rotation
from secret_update_manager import update_secret_policy, update_secret_rotation
from db_manager import create_user, delete_user, grant_privileges, user_exists, generate_password, list_users, reset_password, db_exists



# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def test_db_connectivity(db_credentials):
    try:
        # Connect to the database using the new credentials
        connection = pymysql.connect(host=db_credentials['host'],
                                     user=db_credentials['username'],
                                     password=db_credentials['password'],
                                     db=db_credentials['db_name'],
                                     port=int(db_credentials['port']),
                                     ssl_verify_identity=True)
        cursor = connection.cursor()

        # Query to get the current date and time
        cursor.execute("SELECT CURRENT_TIMESTAMP;")
        current_time = cursor.fetchone()
        logger.info(f"Current time in database: {current_time[0]}")

        # Query to get the current user
        cursor.execute("SELECT USER();")
        current_user = cursor.fetchone()
        logger.info(f"Current user in database: {current_user[0]}")

        # Close the database connection
        cursor.close()
        connection.close()

        return True, "Database connectivity test successful."

    except pymysql.MySQLError as e:
        logger.error(f"Connectivity test failed: {e}")
        return False, f"Database connectivity test failed: {e}"

def format_as_row(items):
    if not items:
        return "No items found."

    # Join items with a comma and a space for row-wise display
    return ", ".join(items)
        

def lambda_handler(event, context):
    try:
        # Extract details from the event
        rds_secret_name = event['rds_secret_name']
        action = event.get('action')
        username = event['username']
        db_name = event['db_name']
        secrets_manager = boto3.client('secretsmanager')

        master_credentials = json.loads(secrets_manager.get_secret_value(SecretId=rds_secret_name)['SecretString'])

        # Connect to the RDS database
        connection = pymysql.connect(host=master_credentials['host'],
                                     user=master_credentials['username'],
                                     password=master_credentials['password'],
                                     db='mysql',
                                     ssl_verify_identity=True)
        cursor = connection.cursor()
        if not db_exists(cursor,db_name) :
            return {'statusCode': 400, 'body': json.dumps(f'Database {db_name} does not exist')}
        if action == 'list_users':
            username = event.get('username', 'list_all_users')
            user_list = list_users(cursor, username)
            row_output = format_as_row(user_list)
            return {'statusCode': 200, 'body': json.dumps(row_output)}

            
            
        if action == 'create_user':
            if user_exists(cursor, username):
                return {'statusCode': 400, 'body': json.dumps(f'User {username} already exists.')}
            
            role = event.get('role', 'readonly')
            password = create_user(cursor, db_name, username)
            grant_privileges(cursor, role, db_name, username)
            
        
            # Get the current date and time in a formatted string
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store the new user's details in Secrets Manager
            new_secret_name = f"rds-{db_name}-{username}-secret"
            new_secret_description = f"Credentials for '{username}' on RDS database '{db_name}'."
            new_secret_tags = [
                {'Key': 'create_by_user_automation', 'Value': 'true'},
                {'Key': 'creation_timestamp', 'Value': current_time} 
                ]
            new_secret_value = {
                'username': username,
                'password': password,
                'host': master_credentials['host'],
                'port': master_credentials['port'],
                'db_name': db_name,
                'engine': 'mysql'
            }
            try:
                secret_response = secrets_manager.create_secret(Name=new_secret_name,
                                                              Description=new_secret_description,
                                                              SecretString=json.dumps(new_secret_value),
                                                              Tags=new_secret_tags)
                new_secret_arn = secret_response['ARN']
                logger.info("Created Secret to store the credentials : " + new_secret_arn)
            except ClientError as e:
                # If secret creation fails, delete the newly created user from the database
                logger.error(f"Failed to create secret in Secrets Manager: {e}")
                delete_user(cursor, username)
                cursor.close()
                connection.close()
                return {'statusCode': 500, 'body': json.dumps('Failed to create secret in Secrets Manager')}
            
           
            # Check if secret rotation is enabled and Rotation Lambda ARN is provided
            try:
                rotation_lambda_arn = os.environ['ROTATION_LAMBDA_ARN']
                logger.info("The rotation lambda arn is " + rotation_lambda_arn)
                rotation_days = os.environ.get('ROTATION_DAYS', 30)
                # logger.info("The rotation days are " , str(rotation_days))
                enable_secret_rotation(new_secret_name, rotation_lambda_arn, rotation_days)
                logger.info(f"Secret rotation enabled with Lambda ARN: {rotation_lambda_arn}")
            except KeyError:
                logger.info("Secret rotation ARN not provided. Secret rotation is not enabled.")

            # Update and apply the resource policy to the new secret
            roles_to_add = event.get('roles', [])
            account_id = context.invoked_function_arn.split(":")[4]
            updated_policy = update_secret_policy_template(roles_to_add, account_id, new_secret_arn)
            secrets_manager.put_resource_policy(SecretId=new_secret_name, ResourcePolicy=updated_policy)
            logger.info(f"Updated resource policy for secret: {new_secret_name}")

            # Conduct a connectivity test if required
            if event.get('connectivity_test', False):
                test_result, message = test_db_connectivity(new_secret_value)
                if not test_result:
                    return {'statusCode': 500, 'body': json.dumps(message)}
                logger.info(message)
        
        elif action == 'password_reset':
            secret_name = event.get('secret_name')
            if not secret_name:
                cursor.close()
                connection.close()
                return {'statusCode': 400, 'body': json.dumps('Secret name is required for password reset.')}

            secret = json.loads(secrets_manager.get_secret_value(SecretId=secret_name)['SecretString'])
            username = secret['username']

            if not user_exists(cursor, username):
                cursor.close()
                connection.close()
                return {'statusCode': 404, 'body': json.dumps(f'User {username} does not exist.')}

            new_password = reset_password(cursor, username)
            secret['password'] = new_password
            secrets_manager.update_secret(SecretId=secret_name, SecretString=json.dumps(secret))
            cursor.close()
            connection.close()
            return {'statusCode': 200, 'body': json.dumps(f'Password reset successfully for user {username}.')}

        elif action == 'delete_user':
            # Check if user exists before attempting to delete
            if not user_exists(cursor, username):
                return {'statusCode': 400, 'body': json.dumps(f'User {username} does not exist.')}
            else:
                delete_user(cursor, username)


            # Delete corresponding secret
            secret_name = f"rds-{db_name}-{username}-secret"
            try:
                secrets_manager.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
                logger.info(f"Deleted the secret for the user {username}")
            except ClientError as e:
                logger.info(f"Unable to delete the secret for user {username}: {e}")
                return {'statusCode': 500, 'body': json.dumps('User deleted in database but failed to delete secret in Secrets Manager')}
        
        elif action == 'update_secret':
            secret_id = event.get('secret_name')

            # Update resource policy if provided
            if 'policy' in event:
                policy = event['policy']
                update_secret_policy(secret_id, policy)
                logger.info(f"Resource policy updated for secret: {secret_id}")

            # Update rotation settings if provided
            if 'rotation_lambda_arn' in event and 'rotation_days' in event:
                rotation_lambda_arn = event['rotation_lambda_arn']
                rotation_days = int(event['rotation_days'])
                update_secret_rotation(secret_id, rotation_lambda_arn, rotation_days)
                logger.info(f"Rotation settings updated for secret: {secret_id}")

        else:
            logger.warning(f"Invalid action specified: {action}")
            return {'statusCode': 400, 'body': json.dumps('Invalid action specified.')}

        cursor.close()
        connection.close()
        return {'statusCode': 200, 'body': json.dumps(f'Action {action} completed successfully for user {username}')}

    except ClientError as e:
        logger.error(f"ClientError: {e}")
        return {'statusCode': 500, 'body': json.dumps('AWS service error')}
    except pymysql.MySQLError as e:
        logger.error(f"MySQLError: {e}")
        return {'statusCode': 500, 'body': json.dumps('MySQL error')}
    except Exception as e:
        logger.error(f"Exception: {e}")
        return {'statusCode': 500, 'body': json.dumps('An unknown error occurred')}
