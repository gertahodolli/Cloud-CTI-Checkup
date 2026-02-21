fields @timestamp, eventSource, eventName, userIdentity.accountId
| filter eventSource = "{{fields.event_source}}" and userIdentity.accountId = "{{metadata.account_id}}"
