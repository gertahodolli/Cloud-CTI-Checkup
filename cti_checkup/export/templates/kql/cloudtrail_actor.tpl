AWSCloudTrail
| where sourceIPAddress == "{{actor.ip}}"
| where userIdentityArn == "{{actor.identity}}"
