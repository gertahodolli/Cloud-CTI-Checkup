title: CloudTrail actor {{actor.actor}}
id: {{actor.ip}}
logsource:
  product: aws
detection:
  condition: {{fields.event_names_field}}
fields:
  identity: {{actor.identity}}
  ip: {{actor.ip}}
