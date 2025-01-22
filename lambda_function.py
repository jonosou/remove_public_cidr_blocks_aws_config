import boto3
import botocore
import json

# Initialize the SNS client
sns = boto3.client('sns')
# Initialize the EC2 client
ec2 = boto3.client("ec2")

APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup"]
# these security groups will not have their public accessible CIDR blocks removed
# replace <security group> with any security group you want to allow with public access
SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS = ["<security group>"]
COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"

def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
                          configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    group_id = configuration_item["configuration"]["groupId"]
    client = ec2

    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        return {
            "compliance_type": NON_COMPLIANT,
            "annotation": "describe_security_groups failure on group " + group_id
        }

    compliance_type = COMPLIANT
    annotation_message = "No unrestricted access on ports 22 or 3389"
    removed_rules = []

    if group_id not in SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS:
        for security_group_rule in response["SecurityGroups"][0]["IpPermissions"]:
            if "FromPort" in security_group_rule and "ToPort" in security_group_rule:
                from_port = security_group_rule["FromPort"]
                to_port = security_group_rule["ToPort"]
                
                # Check if the rule covers port 22 or 3389
                if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                    for r in security_group_rule.get("IpRanges", []):
                        if r["CidrIp"] in ["0.0.0.0/0", "::/0"]:
                            print(f"Found Non Compliant Rule in Security Group: {group_id}")
                            rule_description = {
                                "GroupId": group_id,
                                "IpPermissions": [{
                                    "IpProtocol": security_group_rule["IpProtocol"],
                                    "FromPort": from_port,
                                    "ToPort": to_port,
                                    "IpRanges": [{"CidrIp": r["CidrIp"]}]
                                }]
                            }
                            
                            try:
                                result = client.revoke_security_group_ingress(**rule_description)
                                if result["Return"]:
                                    removed_rules.append(rule_description["IpPermissions"][0])
                                    compliance_type = COMPLIANT
                                    annotation_message = f"Removed unrestricted access rule for port(s) {from_port}-{to_port}"
                                else:
                                    compliance_type = NON_COMPLIANT
                                    annotation_message = f"Failed to remove unrestricted access rule for port(s) {from_port}-{to_port}"
                            except botocore.exceptions.ClientError as e:
                                compliance_type = NON_COMPLIANT
                                annotation_message = f"Error removing rule: {str(e)}"
                            
                            print(f"Result: {compliance_type}")

    return {
        "compliance_type": compliance_type,
        "annotation": annotation_message,
        "group_id": group_id,
        "removed_rules": removed_rules
    }

def lambda_handler(event, context):
    print("Lambda function invoked")

    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]

    evaluation = evaluate_compliance(configuration_item)

    # Only send SNS notification if rules were removed
    if evaluation["removed_rules"]:
        sns_message = f"Security group {evaluation['group_id']} was modified.\n"
        sns_message += "The following rules were removed:\n"
        for rule in evaluation["removed_rules"]:
            sns_message += json.dumps(rule, indent=2) + "\n"

        # Send notification
        try:
            sns.publish(
                # replace <topicArnSNS> with your SNS Topic ARN
                TopicArn='<topicArnSNS>',
                Message=sns_message,
                Subject='Security Group Modification Notification'
            )
            print("SNS notification sent successfully")
        except Exception as e:
            print(f"Failed to send SNS notification: {str(e)}")
    else:
        print(f"No changes were made to security group {evaluation['group_id']}. SNS notification not sent.")

    config = boto3.client('config')

    # the call to put_evaluations is required to inform aws config about the changes
    response = config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])

