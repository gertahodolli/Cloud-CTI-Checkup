"""AI configuration loading and validation."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cti_checkup.core.config_utils import get_bool, get_int, get_list_str


def load_ai_config(cfg: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Load and validate AI configuration.

    Args:
        cfg: Full configuration dictionary.

    Returns:
        Tuple of (enabled, config_dict, error_message).
        If enabled is False or error_message is set, config_dict may be None.
    """
    ai_cfg = cfg.get("ai")
    if not isinstance(ai_cfg, dict):
        return False, None, None  # AI not configured, not an error

    enabled = get_bool(ai_cfg, ["enabled"])
    if enabled is None:
        return False, None, None  # Not explicitly enabled
    if not enabled:
        return False, None, None  # Explicitly disabled

    # Validate required fields when enabled
    provider = ai_cfg.get("provider")
    if not provider:
        return True, None, "ai.enabled=true but ai.provider is missing."

    if provider not in ("openai", "azure_openai", "local", "none"):
        return True, None, f"Unsupported ai.provider: {provider}"

    if provider == "none":
        return False, None, None  # Explicitly disabled via provider

    # Extract summarize.cloudtrail config
    summarize_cfg = ai_cfg.get("summarize") or {}
    cloudtrail_cfg = summarize_cfg.get("cloudtrail") or {}

    config = {
        "enabled": True,
        "provider": provider,
        "model": ai_cfg.get("model", "gpt-4o"),
        "base_url": ai_cfg.get("base_url", "https://api.openai.com/v1"),
        "timeout_seconds": get_int(ai_cfg, ["timeout_seconds"]) or 60,
        "temperature": float(ai_cfg.get("temperature", 0.3)),
        "max_tokens": get_int(ai_cfg, ["max_tokens"]) or 4096,
        "max_input_events": get_int(ai_cfg, ["max_input_events"]) or 50000,
        # CloudTrail summarization config
        "summarize": {
            "cloudtrail": {
                "top_n_actors": get_int(cloudtrail_cfg, ["top_n_actors"]) or 10,
                "top_n_events": get_int(cloudtrail_cfg, ["top_n_events"]) or 20,
                "max_resources": get_int(cloudtrail_cfg, ["max_resources"]) or 50,
            }
        },
        # Redaction config
        "redaction": {
            "enabled": get_bool(ai_cfg.get("redaction") or {}, ["enabled"]) or False,
            "fields": get_list_str(ai_cfg.get("redaction") or {}, ["fields"]) or [
                "accessKeyId",
                "userName",
                "sessionContext.sessionIssuer.userName",
            ],
        },
        # Optional prompt templates directory
        "prompt_templates_dir": ai_cfg.get("prompt_templates_dir"),
    }

    # Azure-specific config
    if provider == "azure_openai":
        config["azure_deployment"] = ai_cfg.get("azure_deployment", "")
        config["azure_api_version"] = ai_cfg.get("azure_api_version", "2024-02-15-preview")
        if not config["azure_deployment"]:
            return True, None, "ai.provider=azure_openai but ai.azure_deployment is missing."

    return True, config, None


def get_suspicious_event_patterns() -> List[Dict[str, Any]]:
    """Return list of suspicious event patterns for deterministic detection.

    These patterns identify common attack sequences in CloudTrail logs.
    """
    return [
        {
            "name": "credential_access",
            "description": "Credential access attempts",
            "events": [
                "GetSecretValue",
                "GetParametersByPath",
                "GetParameter",
                "DescribeSecret",
                "ListSecrets",
            ],
        },
        {
            "name": "discovery",
            "description": "Discovery and enumeration activity",
            "events": [
                "DescribeInstances",
                "ListBuckets",
                "ListUsers",
                "ListRoles",
                "ListPolicies",
                "GetAccountAuthorizationDetails",
                "DescribeSecurityGroups",
                "DescribeVpcs",
                "DescribeSubnets",
            ],
        },
        {
            "name": "privilege_escalation",
            "description": "Privilege escalation attempts",
            "events": [
                "CreatePolicyVersion",
                "SetDefaultPolicyVersion",
                "AttachUserPolicy",
                "AttachRolePolicy",
                "AttachGroupPolicy",
                "PutUserPolicy",
                "PutRolePolicy",
                "PutGroupPolicy",
                "CreateAccessKey",
                "CreateLoginProfile",
                "UpdateLoginProfile",
                "AddUserToGroup",
                "UpdateAssumeRolePolicy",
                "PassRole",
                "AssumeRole",
            ],
        },
        {
            "name": "persistence",
            "description": "Persistence mechanisms",
            "events": [
                "CreateUser",
                "CreateRole",
                "CreateAccessKey",
                "CreateLoginProfile",
                "PutRolePolicy",
                "AttachRolePolicy",
            ],
        },
        {
            "name": "defense_evasion",
            "description": "Defense evasion techniques",
            "events": [
                "DeleteTrail",
                "StopLogging",
                "UpdateTrail",
                "DeleteFlowLogs",
                "DeleteEventBus",
                "DisableRule",
                "DeleteRule",
                "PutBucketLogging",
                "DeleteBucketPolicy",
            ],
        },
        {
            "name": "exfiltration",
            "description": "Data exfiltration indicators",
            "events": [
                "GetObject",
                "CopyObject",
                "GetBucketPolicy",
                "PutBucketPolicy",
                "CreateSnapshot",
                "CopySnapshot",
                "ModifySnapshotAttribute",
                "ShareSnapshot",
            ],
        },
        {
            "name": "impact",
            "description": "Impact/destruction attempts",
            "events": [
                "DeleteBucket",
                "DeleteObject",
                "DeleteSnapshot",
                "DeleteVolume",
                "TerminateInstances",
                "DeleteDBInstance",
                "DeleteDBCluster",
            ],
        },
    ]


def get_console_login_events() -> List[str]:
    """Return events related to console login."""
    return [
        "ConsoleLogin",
        "CheckMfa",
        "GetFederationToken",
        "GetSessionToken",
    ]


def get_auth_failure_error_codes() -> List[str]:
    """Return error codes indicating authentication/authorization failures."""
    return [
        "AccessDenied",
        "UnauthorizedAccess",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "MalformedPolicyDocument",
        "InvalidIdentityToken",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidAccessKeyId",
        "TokenRefreshRequired",
    ]
