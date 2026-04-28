import requests, random, time, uuid

API_URL = 'https://yg1h9ibm76.execute-api.us-east-1.amazonaws.com/prod/event'

ATTACK_TYPES = ['brute_force', 'sql_inject', 'port_scan', 'xss_attempt', 'ddos', 'path_traversal']
SOURCE_IPS = [
    '8.8.8.8',        # US - Google
    '1.1.1.1',        # AU - Cloudflare
    '185.220.101.34', # DE - Tor exit
    '45.33.32.156',   # US - Linode
    '103.21.244.0',   # SG - Singapore
    '41.231.11.100',  # TN - Tunisia
    '196.216.2.1',    # ZA - South Africa
    '200.160.2.3',    # BR - Brazil
    '14.102.70.1',    # IN - India
    '213.180.141.140',# RU - Yandex Russia
    '5.9.32.230',     # DE - Germany
    '89.234.157.254', # FR - France
    '31.13.64.1',     # IE - Facebook Ireland
    '203.208.60.1',   # CN - Google China
    '176.9.0.1',      # DE - Hetzner
]
TARGETS = ['/admin', '/login', '/api/users', '/wp-admin', '/etc/passwd', '/search']
USER_AGENTS = [
    'sqlmap/1.7', 'Nikto/2.1', 'Mozilla/5.0',
    'python-requests/2.28', 'curl/7.88', 'Nmap Scripting Engine'
]
WEIGHTS = [25, 15, 20, 15, 10, 15]

print("Simulator running. Ctrl+C to stop.\n")
while True:
    attack_type = random.choices(ATTACK_TYPES, weights=WEIGHTS)[0]
    payload = {
        'eventId':    str(uuid.uuid4()),
        'attackType': attack_type,
        'sourceIp':   random.choice(SOURCE_IPS),
        'targetUrl':  random.choice(TARGETS),
        'userAgent':  random.choice(USER_AGENTS),
        'method':     random.choice(['GET', 'POST', 'PUT']),
        'statusCode': random.choice([200, 403, 404, 500]),
        'timestamp':  int(time.time() * 1000),
        'payload':    f"sample_{attack_type}_{random.randint(1000,9999)}"
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=5)
        sev = 'CRIT' if attack_type in ('sql_inject','ddos') else 'HIGH' if attack_type in ('xss_attempt','path_traversal') else 'MED'
        print(f"[{sev}] {attack_type:<18} {payload['sourceIp']:<18} → {r.status_code}")
    except Exception as e:
        print(f"[ERR] {e}")
    time.sleep(random.uniform(0.3, 1.2))