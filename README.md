# Real-time-Cybersecurity-Threat-Intelligence

Stream network events / login attempts Lambda detects: brute force, SQL injection, port scanning Live attack map visualization (world map with attack origins) Auto-blocks IPs via WAF Stack: Lambda + WAF + DynamoDB + IPInfo API + D3.js map





\# Real-time Cybersecurity Threat Intelligence Platform



🔴 LIVE DASHBOARD: http://threat-intel-archive-godfrey.s3-website-us-east-1.amazonaws.com/dashboard/index.html



\## Architecture

Attackers → API Gateway → Lambda (ingest) → SQS → Lambda (classifier)

→ DynamoDB + S3 + SNS + Slack → Live Dashboard



\## 6 Attack Types

SQL Injection, DDoS, XSS, Path Traversal, Brute Force, Port Scan



\## Team Structure

\- Part 1: Infrastructure \& Backend (lambdas/, cloudwatch/)

\- Part 2: API \& Integration (simulator/, API Gateway)

\- Part 3: Frontend \& Dashboard (dashboard/)



\## Setup

See docs/api.md for API documentation.

See .env.example for required environment variables.



\## AWS Services

\- API Gateway, Lambda (x3), SQS, DynamoDB (x2), S3, SNS, CloudWatch



\## Resume Project

aws lambda put-function-concurrency --function-name threat-ingest --reserved-concurrent-executions 100 --region us-east-1

aws lambda put-function-concurrency --function-name threat-classifier --reserved-concurrent-executions 100 --region us-east-1

aws lambda put-function-concurrency --function-name threat-reader --reserved-concurrent-executions 100 --region us-east-1

aws lambda update-event-source-mapping --uuid e424d970-ab9e-4a4a-b27a-04dfa8cf59e3 --enabled --region us-east-1

aws cloudwatch enable-alarm-actions --alarm-names "threat-ingest-errors" "threat-classifier-errors" "threat-reader-errors" "threat-surge-detected" --region us-east-1

