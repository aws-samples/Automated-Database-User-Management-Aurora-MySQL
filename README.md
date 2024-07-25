# Centralized Database User Management using AWS Lambda and SSM

This project provides an AWS Lambda function to manage MySQL database users. The Lambda function can be used to create, delete, update grants, or reset the password of a user. Additionally, it integrates with AWS Secrets Manager for secret management. The function is designed to be triggered via an AWS Systems Manager (SSM) Automation document.

# Features

|    Action           |  Description                                                      |
|---------------------|-------------------------------------------------------------------|
| User Creation       |  Create a new MySQL database user.                                |
| User Deletion       | Delete an existing MySQL database user and its associated secret. |
| Update User Grant   | Update privileges of an existing MySQL database user.             |
| Reset User Password | Reset password for an existing MySQL database user.               |


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

