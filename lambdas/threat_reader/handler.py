import json, boto3
from boto3.dynamodb.conditions import Key
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
threat_table = dynamodb.Table('ThreatEvents')
blocked_table = dynamodb.Table('BlockedIPs')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

def lambda_handler(event, context):
    path = event.get('path', '') or event.get('rawPath', '')
    headers = {'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json'}

    if '/stats' in path:
        resp = threat_table.scan(Limit=200)
        items = resp.get('Items', [])
        by_type = {}
        by_severity = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        by_country = {}
        for item in items:
            t = item.get('attackType', 'unknown')
            by_type[t] = by_type.get(t, 0) + 1
            s = item.get('severity', 'LOW')
            by_severity[s] = by_severity.get(s, 0) + 1
            c = item.get('country', 'Unknown')
            by_country[c] = by_country.get(c, 0) + 1
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'total': len(items),
                'byType': by_type,
                'bySeverity': by_severity,
                'byCountry': by_country
            }, cls=DecimalEncoder)
        }

    if '/blocked' in path:
        resp = blocked_table.scan()
        items = resp.get('Items', [])
        items_sorted = sorted(items, key=lambda x: x.get('blockedAt', 0), reverse=True)
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(items_sorted, cls=DecimalEncoder)
        }

    limit = int((event.get('queryStringParameters') or {}).get('limit', 100))
    resp = threat_table.scan(Limit=limit)
    items = sorted(resp.get('Items', []), key=lambda x: x.get('timestamp', 0), reverse=True)
    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps(items, cls=DecimalEncoder)
    }