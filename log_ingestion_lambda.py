# lambda_function.py for log-ingestion-lambda

# Standard library imports
import json
import gzip
import os
import urllib3

# Third-party imports (Boto3 is included in Lambda runtime)
import boto3

# --- AWS Client Initialization ---
# It's best practice to initialize clients outside the handler
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
lambda_client = boto3.client('lambda')
secrets_client = boto3.client('secretsmanager')
http = urllib3.PoolManager()

# --- Environment Variable Loading ---
# Load variables once to avoid repeated lookups
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_LAMBDA_NAME = os.environ.get('REMEDIATION_LAMBDA_NAME')
SECRET_ARN = os.environ.get('SECRET_ARN')


# --- Helper Functions ---
# Each function has a specific, single purpose.

def get_gemini_api_key():
    """
    Fetches the Gemini API key from AWS Secrets Manager.
    This function is defined to be separate from the main handler for clarity.
    """
    print("Attempting to retrieve secret from Secrets Manager...")
    try:
        response = secrets_client.get_secret_value(SecretId=SECRET_ARN)
        secret = json.loads(response['SecretString'])
        print("Successfully retrieved secret.")
        return secret['GEMINI_API_KEY']
    except Exception as e:
        print(f"FATAL: Error retrieving secret from Secrets Manager: {e}")
        # Raising an exception here will stop the function execution if the key can't be fetched
        raise e


def analyze_event_with_llm(event_data, api_key):
    """
    Sends event data to the Gemini API for analysis and returns the parsed JSON response.
    This function handles the prompt engineering and API call.
    """
    print("Sending event to LLM for analysis...")
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    
    prompt = f"""
    You are a senior AWS security analyst. Your task is to analyze the following AWS CloudTrail event and provide a structured risk assessment.
    The event indicates that a security group rule was added.
    Based on the event data provided, perform the following actions:
    1. Determine the risk score on a scale of 1 to 10, where 10 is the most critical. A rule allowing all traffic (0.0.0.0/0) to a sensitive port like 22 (SSH) or 3389 (RDP) should be considered a high risk (8 or above).
    2. Identify the corresponding MITRE ATT&CK Tactic and Technique. For an overly permissive ingress rule, this is likely 'Initial Access' (TA0001) and 'External Remote Services' (T1133).
    3. Write a brief, clear summary of the threat.
    4. Recommend an action: either "AUTOMATED_REMEDIATION" for high-risk events or "MANUAL_REVIEW" for lower-risk events.
    
    Respond ONLY with a single, minified JSON object with no newlines. The JSON object must have these exact keys: "risk_score", "mitre_tactic", "mitre_technique", "summary", and "recommended_action".

    Event Data:
    {json.dumps(event_data)}
    """
    
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = http.request('POST', api_url, body=json.dumps(payload).encode('utf-8'), headers=headers)
        if response.status == 200:
            response_data = json.loads(response.data.decode('utf-8'))
            content_text = response_data['candidates'][0]['content']['parts'][0]['text']
            print("Successfully received analysis from LLM.")
            return json.loads(content_text)
        else:
            print(f"ERROR from Gemini API: Status={response.status}, Body={response.data.decode('utf-8')}")
            return None
    except Exception as e:
        print(f"ERROR during LLM API call: {e}")
        return None


def lambda_handler(event, context):
    """
    Main function to process CloudTrail logs, analyze with an LLM, and trigger
    a risk-based response.
    """
    # --- Initial Checks ---
    if not all([SNS_TOPIC_ARN, REMEDIATION_LAMBDA_NAME, SECRET_ARN]):
        print("FATAL: Missing one or more required environment variables. Aborting.")
        return

    try:
        api_key = get_gemini_api_key()
    except Exception as e:
        print(f"FATAL: Could not get API key. Aborting. Error: {e}")
        return

    # --- S3 Event Processing ---
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    try:
        local_gzipped_path = f"/tmp/{os.path.basename(key)}"
        s3_client.download_file(bucket, key, local_gzipped_path)

        with gzip.open(local_gzipped_path, 'rt') as f:
            log_data = json.load(f)

        # --- Event Loop and Analysis ---
        for record in log_data.get('Records', []):
            if record.get('eventName') == 'AuthorizeSecurityGroupIngress':
                print(f"Found AuthorizeSecurityGroupIngress event for user {record.get('userIdentity', {}).get('arn', 'N/A')}. Analyzing...")
                
                analysis = analyze_event_with_llm(record, api_key)
                
                if not analysis:
                    print("Analysis failed or returned no data. Skipping this event.")
                    continue

                print(f"LLM Analysis Received: {json.dumps(analysis)}")
                risk_score = analysis.get('risk_score', 0)
                
                remediation_status = "Action not determined." # Default status

                # --- Risk-Based Response Logic ---
                if analysis.get('recommended_action') == "AUTOMATED_REMEDIATION" and risk_score >= 8:
                    print(f"High-risk event detected (Score: {risk_score}). Invoking automated remediation.")
                    
                    try:
                        group_id = record['requestParameters']['groupId']
                        rule_to_revoke = record['requestParameters']['ipPermissions']['items'][0]
                        
                        # Manually build the IpRanges list to ensure correct format
                        ip_ranges_to_revoke = []
                        for item in rule_to_revoke.get('ipRanges', {}).get('items', []):
                            ip_ranges_to_revoke.append({'CidrIp': item['cidrIp']})

                        # Only proceed if we actually found a CIDR to revoke
                        if not ip_ranges_to_revoke:
                            raise ValueError("Could not find IpRanges to revoke in the event.")

                        remediation_payload = {
                            "security_group_id": group_id,
                            "rule_details": {
                                "IpProtocol": rule_to_revoke.get('ipProtocol'),
                                "FromPort": rule_to_revoke.get('fromPort'),
                                "ToPort": rule_to_revoke.get('toPort'),
                                "IpRanges": ip_ranges_to_revoke
                            }
                        }
                        
                        print(f"Constructed remediation payload: {json.dumps(remediation_payload)}")

                        lambda_client.invoke(
                            FunctionName=REMEDIATION_LAMBDA_NAME,
                            InvocationType='Event',
                            Payload=json.dumps(remediation_payload)
                        )
                        remediation_status = "AUTOMATED REMEDIATION INITIATED."
                        
                    except (KeyError, ValueError) as e:
                        print(f"ERROR: Could not construct remediation payload. Missing key or value: {e}")
                        remediation_status = "REMEDIATION FAILED: Malformed event data."
                else:
                    print(f"Low/Medium risk event (Score: {risk_score}). No automated action taken.")
                    remediation_status = "MANUAL REVIEW REQUIRED."

                # --- Final Notification ---
                summary_for_subject = analysis.get('summary', 'Analysis Summary Missing').replace('\n', ' ').strip()
                if len(summary_for_subject) > 60:
                    summary_for_subject = summary_for_subject[:57] + "..."

                subject = f"Security Alert [Risk: {risk_score}/10]: {summary_for_subject}"
                full_summary = analysis.get('summary', 'N/A')

                message = (
                    f"## AWS Security Alert - AI Analysis ##\n\n"
                    f"Risk Score: {risk_score}/10\n"
                    f"Summary: {full_summary}\n"
                    f"MITRE Tactic: {analysis.get('mitre_tactic', 'N/A')}\n"
                    f"MITRE Technique: {analysis.get('mitre_technique', 'N/A')}\n\n"
                    f"--- Event Details ---\n"
                    f"User: {record.get('userIdentity', {}).get('arn', 'N/A')}\n"
                    f"Source IP: {record.get('sourceIPAddress', 'N/A')}\n"
                    f"Security Group ID: {record.get('requestParameters', {}).get('groupId', 'N/A')}\n\n"
                    f"Status: {remediation_status}"
                )
                
                print("Publishing final alert to SNS.")
                sns_client.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject=subject)

    except Exception as e:
        print(f"FATAL ERROR in main handler while processing S3 file {key}: {e}")
        raise
