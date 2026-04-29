\# API Documentation



\## Base URL

https://yg1h9ibm76.execute-api.us-east-1.amazonaws.com/prod



\## Endpoints



\### POST /event

Ingest a threat event.

Body:

{

&#x20; "attackType": "sql\_inject",

&#x20; "sourceIp": "1.2.3.4",

&#x20; "targetUrl": "/login"

}



\### GET /threats?limit=100

Returns recent threat events from DynamoDB.



\### GET /stats

Returns aggregated stats:

\- total events

\- by severity

\- by attack type

\- by country



\### GET /blocked

Returns auto-blocked IPs (HIGH + CRITICAL severity).



\## Attack Types

\- sql\_inject    (risk: 95, CRITICAL)

\- ddos          (risk: 90, CRITICAL)

\- path\_traversal(risk: 85, HIGH)

\- xss\_attempt   (risk: 80, HIGH)

\- brute\_force   (risk: 75, HIGH)

\- port\_scan     (risk: 60, MEDIUM)

