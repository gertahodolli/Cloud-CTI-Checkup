title: IAM identity {{identity.identity}}
id: {{identity.identity}}
logsource:
  product: aws
detection:
  condition: {{fields.risk_factors_field}}
fields:
  risk_score: {{identity.risk_score}}
