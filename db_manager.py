import logging
import string
import secrets

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def db_exists(cursor, db_name):
    logger.info(f"Checking if db {db_name} exists")
    query = "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = %s"
    cursor.execute(query, (db_name,))
    #cursor.execute(f"select  COUNT(*) from information_schema.schemata where schema_name = '{db_name}'")
    return cursor.fetchone()[0] > 0

def user_exists(cursor, username):
    logger.info(f"Checking if user {username} exists")
    query = "SELECT COUNT(*) FROM mysql.user WHERE user = %s"
    cursor.execute(query, (username,))
    #cursor.execute(f"SELECT COUNT(*) FROM mysql.user WHERE user = '{username}'")
    return cursor.fetchone()[0] > 0

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def create_user(cursor, db_name, username):
    password = generate_password()
    logger.info(f"Creating new user: {username} with an auto-generated password")
    cursor.execute(f"CREATE USER '{username}'@'%' IDENTIFIED BY '{password}';")
    logger.info(f"User {username} created successfully")
    return password


def delete_user(cursor, username):
    logger.info(f"Deleting user: {username}")
    cursor.execute(f"DROP USER '{username}'@'%'")
    cursor.execute("FLUSH PRIVILEGES;")
    logger.info(f"User {username} deleted successfully")

def grant_privileges(cursor, role, db_name, username):
    logger.info(f"Granting {role} privileges to user {username}")
    if role == 'admin':
        cursor.execute(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{username}'@'%';")
    elif role == 'readwrite':
        cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{db_name}`.* TO '{username}'@'%';")
    elif role == 'readonly':
        cursor.execute(f"GRANT SELECT ON `{db_name}`.* TO '{username}'@'%';")
    else:
        raise ValueError("Invalid role specified")
    cursor.execute("FLUSH PRIVILEGES;")
    logger.info("Privileges granted successfully")

def list_users(cursor, username=None):
    try:
        # If a specific username is provided, fetch its grants
        if username and username != 'list_all_users':
            cursor.execute(f"SHOW GRANTS FOR '{username}'@'%';")
            grants = cursor.fetchall()
            if not grants:
                logger.info(f"No grants found for user {username}.")
                return []
            return [grant[0] for grant in grants]

        # If 'list_all_users' keyword or no username is provided, list all users
        if not username or username == 'list_all_users':
            cursor.execute("SELECT User FROM mysql.user;")
            users = cursor.fetchall()

            if not users:
                logger.info("No users found in the database.")
                return []

            # Extract usernames from the query result
            usernames = [user[0] for user in users]
            return usernames

    except pymysql.MySQLError as e:
        logger.error(f"Error in list_users: {e}")
        raise


def reset_password(cursor, username):
    new_password = generate_password()  # Using the generate_password function defined earlier
    try:
        logger.info(f"Resetting password for user {username}")
        cursor.execute(f"ALTER USER '{username}'@'%' IDENTIFIED BY '{new_password}';")
        cursor.execute("FLUSH PRIVILEGES;")
        logger.info(f"Password reset successfully for user {username}")
        return new_password
    except pymysql.MySQLError as e:
        logger.error(f"Error resetting password for user {username}: {e}")
        raise
