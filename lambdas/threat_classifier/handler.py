import json, boto3, time, os
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
sns = boto3.client('sns')

THREAT_TABLE = dynamodb.Table('ThreatEvents')
BLOCKED_TABLE = dynamodb.Table('BlockedIPs')
ARCHIVE_BUCKET = 'threat-intel-archive-godfrey'
SNS_ARN = os.environ.get('SNS_TOPIC_ARN', '')

RULES = {
    'brute_force':    {'risk': 75,  'severity': 'HIGH'},
    'sql_inject':     {'risk': 95,  'severity': 'CRITICAL'},
    'port_scan':      {'risk': 60,  'severity': 'MEDIUM'},
    'xss_attempt':    {'risk': 80,  'severity': 'HIGH'},
    'ddos':           {'risk': 90,  'severity': 'CRITICAL'},
    'path_traversal': {'risk': 85,  'severity': 'HIGH'},
}

GEO_DB = {
    '192.168.1.1':   {'country': 'Russia',        'lat': 55.75,  'lon': 37.62},
    '10.0.0.1':      {'country': 'China',          'lat': 39.90,  'lon': 116.39},
    '172.16.0.1':    {'country': 'North Korea',    'lat': 39.03,  'lon': 125.75},
    '203.0.113.1':   {'country': 'Iran',           'lat': 35.69,  'lon': 51.39},
    '198.51.100.1':  {'country': 'Brazil',         'lat': -23.55, 'lon': -46.63},
    '185.220.101.1': {'country': 'Romania',        'lat': 44.43,  'lon': 26.10},
    '91.108.4.1':    {'country': 'Ukraine',        'lat': 50.45,  'lon': 30.52},
    '45.142.212.1':  {'country': 'Germany',        'lat': 52.52,  'lon': 13.40},
    '77.88.55.1':    {'country': 'Netherlands',    'lat': 52.37,  'lon': 4.90},
    '104.21.14.1':   {'country': 'United States',  'lat': 37.09,  'lon': -95.71},
}

def lambda_handler(event, context):
    for record in event['Records']:
        payload = json.loads(record['body'])
        attack_type = payload.get('attackType', 'unknown')
        source_ip = payload.get('sourceIp', '0.0.0.0')
        rule = RULES.get(attack_type, {'risk': 30, 'severity': 'LOW'})
        geo = GEO_DB.get(source_ip, {'country': 'Unknown', 'lat': 0, 'lon': 0})

        enriched = {
            **payload,
            'riskScore': rule['risk'],
            'severity': rule['severity'],
            'country': geo['country'],
            'lat': str(geo['lat']),
            'lon': str(geo['lon']),
            'classified': True,
            'timestamp': payload.get('timestamp', int(time.time() * 1000)),
        }

        THREAT_TABLE.put_item(Item={
            k: Decimal(str(v)) if isinstance(v, float) else v
            for k, v in enriched.items()
        })

        s3.put_object(
            Bucket=ARCHIVE_BUCKET,
            Key=f"events/{attack_type}/{payload['eventId']}.json",
            Body=json.dumps(enriched),
            ContentType='application/json'
        )

        if rule['severity'] in ('HIGH', 'CRITICAL'):
            BLOCKED_TABLE.put_item(Item={
                'ip': source_ip,
                'blockedAt': int(time.time() * 1000),
                'reason': attack_type,
                'severity': rule['severity']
            })

        if rule['severity'] == 'CRITICAL' and SNS_ARN:
            sns.publish(
                TopicArn=SNS_ARN,
                Subject=f"CRITICAL THREAT: {attack_type} from {source_ip}",
                Message=(
                    f"Attack Type: {attack_type}\n"
                    f"Source IP:   {source_ip}\n"
                    f"Country:     {geo['country']}\n"
                    f"Risk Score:  {rule['risk']}/100\n"
                    f"Event ID:    {payload['eventId']}\n"
                    f"Time:        {time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            )

    return {'statusCode': 200}