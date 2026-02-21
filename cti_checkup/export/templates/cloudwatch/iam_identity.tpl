fields @timestamp, userIdentity.arn
| filter userIdentity.arn = "{{identity.identity}}"
