title: {{finding.issue}}
id: {{finding.finding_id}}
logsource:
  product: aws
detection:
  condition: {{fields.event_source}}
fields:
  resource_id: {{finding.resource_id}}
  account_id: {{metadata.account_id}}
