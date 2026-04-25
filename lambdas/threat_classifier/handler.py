import json, boto3, time, os, urllib.request, urllib.error
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
sns = boto3.client('sns')

THREAT_TABLE = dynamodb.Table('ThreatEvents')
BLOCKED_TABLE = dynamodb.Table('BlockedIPs')
ARCHIVE_BUCKET = 'threat-intel-archive-godfrey'
SNS_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', '')

RULES = {
    'brute_force':    {'risk': 75,  'severity': 'HIGH'},
    'sql_inject':     {'risk': 95,  'severity': 'CRITICAL'},
    'port_scan':      {'risk': 60,  'severity': 'MEDIUM'},
    'xss_attempt':    {'risk': 80,  'severity': 'HIGH'},
    'ddos':           {'risk': 90,  'severity': 'CRITICAL'},
    'path_traversal': {'risk': 85,  'severity': 'HIGH'},
}

SEV_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
}

def send_slack(attack_type, source_ip, country, risk, severity, event_id):
    if not SLACK_WEBHOOK:
        return
    emoji = SEV_EMOJI.get(severity, '⚪')
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity} THREAT DETECTED"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Attack Type:*\n`{attack_type.upper().replace('_',' ')}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{source_ip}`"},
                    {"type": "mrkdwn", "text": f"*Country:*\n{country}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk}/100`"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Event ID: `{event_id}` • {time.strftime('%Y-%m-%d %H:%M:%S UTC')}"}
                ]
            },
            {"type": "divider"}
        ]
    }
    try:
        data = json.dumps(message).encode('utf-8')
        req = urllib.request.Request(
            SLACK_WEBHOOK,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"Slack error: {e}")

def get_geo(ip):
    # fallback for private/test IPs
    private = ['192.168.','10.','172.16.','127.','0.']
    if any(ip.startswith(p) for p in private):
        return {'country':'Private Network','lat':0,'lon':0}
    try:
        req = urllib.request.Request(
            f'https://ipinfo.io/{ip}/json',
            headers={'Accept':'application/json'}
        )
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        loc = data.get('loc','0,0').split(',')
        return {
            'country': data.get('country','Unknown'),
            'city':    data.get('city',''),
            'org':     data.get('org',''),
            'lat':     float(loc[0]) if len(loc)==2 else 0,
            'lon':     float(loc[1]) if len(loc)==2 else 0,
        }
    except:
        return {'country':'Unknown','lat':0,'lon':0}

def lambda_handler(event, context):
    for record in event['Records']:
        payload = json.loads(record['body'])
        attack_type = payload.get('attackType', 'unknown')
        source_ip = payload.get('sourceIp', '0.0.0.0')
        rule = RULES.get(attack_type, {'risk': 30, 'severity': 'LOW'})
        geo = get_geo(source_ip)

        enriched = {
            **payload,
            'riskScore': rule['risk'],
            'severity': rule['severity'],
            'country': geo['country'],
            'city': geo.get('city',''),
            'org': geo.get('org',''),
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

        if rule['severity'] == 'CRITICAL':
            send_slack(
                attack_type, source_ip,
                geo['country'], rule['risk'],
                rule['severity'], payload['eventId']
            )
            if SNS_ARN:
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