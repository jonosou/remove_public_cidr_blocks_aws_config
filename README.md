# AWS Security Group Public Access Removal

## Overview

This AWS Lambda function automatically removes public access (0.0.0.0/0 and ::/0) from EC2 Security Groups. It works in conjunction with AWS Config to evaluate and modify security group rules, enhancing the security posture of your AWS environment.

## Features

- Automatically evaluates EC2 Security Groups for compliance
- Removes public access (0.0.0.0/0 and ::/0) from non-compliant security groups
- Sends SNS notifications when changes are made to security groups
- Integrates with AWS Config for compliance reporting

## Prerequisites

- AWS account with appropriate permissions
- AWS Lambda
- AWS Config
- Amazon SNS topic for notifications

## Configuration

1. **APPLICABLE_RESOURCES**: List of resource types to evaluate (default: ["AWS::EC2::SecurityGroup"])
2. **SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS**: List of security group IDs that are allowed to have public access
3. **SNS Topic ARN**: Update the SNS Topic ARN in the `sns.publish()` call

## Functionality

1. The function is triggered by AWS Config
2. It evaluates the compliance of the security group based on its rules
3. If non-compliant (contains public access), it removes the offending rules
4. Sends an SNS notification with details of the removed rules
5. Updates the compliance status in AWS Config

## Compliance States

- COMPLIANT: Security group has no public access or is in the allowed list
- NON_COMPLIANT: Security group has public access and removal failed
- NOT_APPLICABLE: Resource is not a security group or has been deleted

## SNS Notifications

An SNS notification is sent when rules are removed from a security group. The notification includes:
- The security group ID
- A list of removed rules with their details

## AWS Config Integration

The function updates the compliance status in AWS Config using the `put_evaluations` call, allowing for centralized compliance monitoring and reporting.

## Error Handling

The function includes error handling for API calls and logs errors for troubleshooting.

## Logging

The function logs various events and results to CloudWatch Logs, including:
- Function invocation
- Evaluation results
- SNS notification status
- Any errors encountered

## Customization

To customize the function:
1. Modify the `SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS` list to include any security groups that should be exempt from this rule
2. Update the SNS Topic ARN to your desired notification channel
3. Adjust the compliance logic in the `evaluate_compliance` function if needed

## Deployment

Deploy this function in AWS Lambda and configure an AWS Config rule to trigger it for EC2 Security Group changes.

## Security Considerations

- Ensure that the Lambda function has the necessary IAM permissions to describe and modify security groups, and to publish to the specified SNS topic.
- This function removes all rules with public access (0.0.0.0/0 and ::/0), not just for specific ports. Adjust the logic if you need to target specific ports or protocols.

## Disclaimer

This script modifies security group rules. Test thoroughly in a non-production environment before deploying to production. Removing public access may impact the functionality of your applications, so ensure you understand the implications before deployment.

    
