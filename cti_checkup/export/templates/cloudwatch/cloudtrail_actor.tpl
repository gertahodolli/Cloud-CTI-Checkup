fields @timestamp, sourceIPAddress, userIdentity.arn
| filter sourceIPAddress = "{{actor.ip}}" and userIdentity.arn = "{{actor.identity}}"
