import boto3
import json
from decimal import Decimal

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('SIEMAlerts')

response = table.scan()
items = response.get('Items', [])

items = sorted(items, key=lambda x: x.get('EventTime', ''), reverse=True)

print(json.dumps(items, indent=2, default=str))
