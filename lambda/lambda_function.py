import json
import gzip
import base64
import boto3
import uuid
import urllib.request
import urllib.error

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("SIEMAlerts")

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:373942188891:siem-alerts"

WATCHED_EVENTS = [
    "ConsoleLogin",
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "StopLogging",
    "DeleteTrail",
    "CreateUser",
    "AttachUserPolicy",
    "PutUserPolicy"
]


def get_severity(event_name, user_identity):
    user_identity = (user_identity or "").lower()

    if "root" in user_identity:
        return "HIGH"

    if event_name in [
        "StopLogging",
        "DeleteTrail",
        "CreateUser",
        "AttachUserPolicy",
        "PutUserPolicy",
        "ConsoleLogin"
    ]:
        return "HIGH"

    if event_name in [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress"
    ]:
        return "MEDIUM"

    return "LOW"


def is_suspicious(ip, event_name, user_identity):
    user_identity = (user_identity or "").lower()

    if "root" in user_identity:
        return True

    if event_name in [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "StopLogging",
        "DeleteTrail",
        "CreateUser",
        "AttachUserPolicy",
        "PutUserPolicy"
    ]:
        return True

    return False


def get_ip_context(ip):
    if ip in ["Unknown", "127.0.0.1", "::1", "AWS Internal"]:
        return {
            "IPReputation": "Unknown",
            "IPCountry": "Unknown",
            "IPCity": "Unknown",
            "ISP": "Unknown"
        }

    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,query"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())

        if data.get("status") == "success":
            return {
                "IPReputation": "Unverified",
                "IPCountry": data.get("country", "Unknown"),
                "IPCity": data.get("city", "Unknown"),
                "ISP": data.get("isp", "Unknown")
            }
    except urllib.error.URLError:
        pass
    except Exception:
        pass

    return {
        "IPReputation": "LookupFailed",
        "IPCountry": "Unknown",
        "IPCity": "Unknown",
        "ISP": "Unknown"
    }


def lambda_handler(event, context):
    cw_data = event["awslogs"]["data"]
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload)
    log_data = json.loads(uncompressed_payload)

    for log_event in log_data["logEvents"]:
        try:
            message = json.loads(log_event["message"])
        except Exception:
            continue

        event_name = message.get("eventName", "")
        source_ip = message.get("sourceIPAddress", "Unknown")
        aws_region = message.get("awsRegion", "Unknown")
        event_time = message.get("eventTime", "Unknown")
        user_identity = message.get("userIdentity", {}).get("arn", "Unknown")

        if event_name in WATCHED_EVENTS:
            severity = get_severity(event_name, user_identity)
            suspicious = is_suspicious(source_ip, event_name, user_identity)
            alert_id = str(uuid.uuid4())
            ip_context = get_ip_context(source_ip)

            alert_message = (
                f"Suspicious AWS Activity Detected\n\n"
                f"Severity: {severity}\n"
                f"Suspicious: {suspicious}\n"
                f"Event Name: {event_name}\n"
                f"User: {user_identity}\n"
                f"Source IP: {source_ip}\n"
                f"Country: {ip_context['IPCountry']}\n"
                f"City: {ip_context['IPCity']}\n"
                f"ISP: {ip_context['ISP']}\n"
                f"IP Reputation: {ip_context['IPReputation']}\n"
                f"Time: {event_time}\n"
                f"AWS Region: {aws_region}\n"
                f"Alert ID: {alert_id}"
            )

            table.put_item(
                Item={
                    "AlertId": alert_id,
                    "EventTime": event_time,
                    "Severity": severity,
                    "IsSuspicious": suspicious,
                    "EventName": event_name,
                    "UserIdentity": user_identity,
                    "SourceIP": source_ip,
                    "AWSRegion": aws_region,
                    "IPReputation": ip_context["IPReputation"],
                    "IPCountry": ip_context["IPCountry"],
                    "IPCity": ip_context["IPCity"],
                    "ISP": ip_context["ISP"]
                }
            )

            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"AWS SIEM Alert - {severity}",
                Message=alert_message
            )

    return {
        "statusCode": 200,
        "body": json.dumps("Processed CloudTrail logs successfully")
    }
