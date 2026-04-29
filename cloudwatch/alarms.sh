#!/bin/bash
SNS_ARN="arn:aws:sns:us-east-1:619071349552:threat-critical-alerts"

FUNCTIONS=("threat-ingest" "threat-classifier" "threat-reader")
for fn in "${FUNCTIONS[@]}"; do
  aws cloudwatch put-metric-alarm \
    --alarm-name "${fn}-errors" \
    --metric-name Errors --namespace AWS/Lambda \
    --dimensions Name=FunctionName,Value=$fn \
    --threshold 3 --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 --period 60 --statistic Sum \
    --alarm-actions $SNS_ARN --region us-east-1
done

aws cloudwatch put-metric-alarm \
  --alarm-name "threat-surge-detected" \
  --metric-name Invocations --namespace AWS/Lambda \
  --dimensions Name=FunctionName,Value=threat-classifier \
  --threshold 50 --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 --period 300 --statistic Sum \
  --alarm-actions $SNS_ARN --region us-east-1

echo "All threat intelligence alarms set."