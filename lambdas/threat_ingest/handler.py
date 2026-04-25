import json, boto3, uuid, time

sqs = boto3.client('sqs', region_name='us-east-1')
QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/619071349552/threat-events-queue'

def lambda_handler(event, context):
    body = json.loads(event.get('body', '{}'))
    body['eventId'] = str(uuid.uuid4())
    body['receivedAt'] = int(time.time() * 1000)
    body['timestamp'] = body.get('timestamp', int(time.time() * 1000))  # ADD THIS
    sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(body))
    return {
        'statusCode': 200,
        'headers': {'Access-Control-Allow-Origin': '*'},
        'body': json.dumps({'status': 'received', 'eventId': body['eventId']})
    }