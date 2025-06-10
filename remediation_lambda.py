# lambda_function.py for remediation-lambda
import json
import boto3

# Initialize EC2 client
ec2_client = boto3.client('ec2')

def lambda_handler(event, context):
    """
    This function receives security group details and revokes the insecure rule.
    The 'event' payload is what you will provide during manual testing.
    Example event:
    {
      "security_group_id": "sg-012345abcdef",
      "rule_details": {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
      }
    }
    """
    print(f"Remediation function triggered with event: {json.dumps(event)}")
    
    try:
        group_id = event['security_group_id']
        rule_to_revoke = event['rule_details']

        print(f"Attempting to revoke rule from Security Group: {group_id}")
        
        # Use the Boto3 client to revoke the security group ingress rule
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[rule_to_revoke]
        )
        
        print(f"Successfully revoked insecure rule from {group_id}.")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Successfully revoked rule from {group_id}")
        }
    except KeyError as e:
        print(f"Error: Missing required key in the event payload: {e}")
        raise
    except Exception as e:
        print(f"Error during remediation: {e}")
        raise
