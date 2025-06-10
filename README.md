# **AI-Powered Cloud Threat Detection & Automated Response Pipeline**

This repository contains the code and documentation for a serverless, event-driven security pipeline built in AWS. The system is designed to automatically detect, analyze with AI, and respond to insecure cloud configurations in real time.

## **High-Level Summary**

This project simulates a real-world DevSecOps environment by creating a system that not only detects an insecure configuration (like a publicly exposed port) but also uses the Google Gemini Large Language Model (LLM) to analyze the risk and triggers an immediate, automated remediation to fix it. This approach significantly reduces the Mean Time to Respond (MTTR) for critical security events.

## **Key Features & Technologies**

* **Threat Detection & Engineering:** AWS CloudTrail, Security Group Analysis, Detection-as-Code  
* **Cloud Architecture & Security:** AWS Lambda, S3, SNS, IAM, Secrets Manager, VPC  
* **Automation & Scripting (DevSecOps):** Python, Boto3, JSON, REST APIs  
* **Generative AI & LLMs:** Google Gemini API Integration, Prompt Engineering for Security Analysis  
* **Incident Response:** Automated Remediation, Alert Enrichment, MITRE ATT\&CK Framework Mapping

## **Architecture & Workflow**

The pipeline operates in a fully automated, serverless workflow:

1. **Logging:** An insecure action (e.g., a user opening a sensitive port to the world in a security group) is recorded by **AWS CloudTrail**.  
2. **Ingestion:** CloudTrail delivers the log file to a central **S3 bucket**, which triggers the log-ingestion-lambda.  
3. **AI Analysis:** The Lambda function parses the log, identifies the suspicious event, and sends the event data to the **Google Gemini API** for a risk assessment. The LLM returns a structured JSON object with a risk score and MITRE ATT\&CK mapping.  
4. **Risk-Based Response:**  
   * If the risk score is high (\>= 8), the Lambda invokes a second remediation-lambda to automatically remove the insecure rule AND publishes a CRITICAL alert to an **SNS Topic**.  
   * If the risk is medium or low, it only publishes a MEDIUM alert for manual review.  
5. **Notification:** The SNS topic sends a detailed, enriched alert via email to the security analyst.

## **Code**

* **lambda\_functions/log\_ingestion\_lambda/**: The primary Python function that orchestrates the detection and analysis workflow.  
* **lambda\_functions/remediation\_lambda/**: The Python function responsible for reverting insecure changes.  
* **iam\_policies/**: Contains the JSON definitions for the least-privilege IAM roles required by the Lambda functions.

## **Challenges & Resolutions**

During development, several real-world technical challenges were encountered and resolved, demonstrating a systematic approach to debugging:

* **LLM API Failure (404 Not Found):** Resolved by analyzing CloudWatch logs to identify an outdated model name in the API endpoint URL and updating it to a current, supported model (gemini-1.5-flash-latest).  
* **SNS Subject Line Error (InvalidParameterException):** Fixed by implementing a data sanitization step in Python to clean and truncate the LLM-generated summary before using it in the SNS subject line, ensuring compliance with the service's character limits and formatting rules.  
* **Remediation Payload Mismatch (ParameterValidationError):** Solved by manually reconstructing the IpRanges list in the JSON payload sent to the remediation function, ensuring it only contained the CidrIp key and stripping any extra fields from the CloudTrail log that the remediation API would reject.

## **Disclaimer**

This project was created in a personal AWS account for educational and portfolio purposes. All resources have been decommissioned to avoid ongoing costs. Do not deploy in a production environment without extensive testing and security reviews.
