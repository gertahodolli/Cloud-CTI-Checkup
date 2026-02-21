AWSCloudTrail
| where eventSource == "{{fields.event_source}}"
| where userIdentityAccountId == "{{metadata.account_id}}"
