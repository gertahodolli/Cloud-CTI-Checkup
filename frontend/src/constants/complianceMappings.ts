// ============================================================
// Compliance: check_id (finding.issue) → framework controls
// Each control is passed if no finding has an issue in its check_ids.
// ============================================================

export interface ComplianceControl {
  id: string;
  name: string;
  /** Finding issue values that violate this control */
  check_ids: string[];
}

export interface FrameworkControlSet {
  name: string;
  short_name: string;
  controls: ComplianceControl[];
}

/**
 * Controls we assess per framework, with mappings from scan check_ids (finding.issue).
 * Total = controls.length, passed = controls with no findings for any of their check_ids.
 */
export const COMPLIANCE_FRAMEWORK_CONTROLS: readonly FrameworkControlSet[] = [
  {
    short_name: 'CIS AWS',
    name: 'CIS AWS Foundations Benchmark',
    controls: [
      { id: '1.4', name: 'Ensure no root account access keys exist', check_ids: ['root_mfa_not_enabled', 'root_mfa_check_failed', 'root_mfa_check_disabled'] },
      { id: '1.10', name: 'Ensure MFA is enabled for all IAM users', check_ids: ['mfa_not_enabled', 'mfa_check_failed'] },
      { id: '1.14', name: 'Ensure access keys are rotated every 90 days or less', check_ids: ['access_key_older_than_threshold'] },
      { id: '1.16', name: 'Ensure IAM policies allow only intended access', check_ids: ['admin_policy_wildcards_detected', 'policy_allow_not_action', 'policy_allow_not_resource', 'policy_privilege_escalation_action', 'admin_policy_check_disabled', 'policy_read_failed', 'inline_policy_read_failed', 'risky_policy_check_disabled'] },
      { id: '1.20', name: 'Ensure access keys are unused for 90 days or less', check_ids: ['access_key_unused_over_threshold', 'access_key_never_used', 'access_key_last_used_lookup_failed', 'missing_max_unused_days_config'] },
      { id: '2.1.1', name: 'Ensure S3 bucket policy allows only authorized requests', check_ids: ['s3_public', 'public_access_enabled', 'list_buckets_failed'] },
      { id: '2.1.2', name: 'Ensure S3 bucket default encryption is enabled', check_ids: ['default_encryption_not_configured', 'default_encryption_check_disabled', 'default_encryption_check_failed', 'default_encryption_algorithm_not_allowed', 'missing_allowed_sse_algorithms_config'] },
      { id: '2.1.3', name: 'Ensure S3 bucket versioning is enabled', check_ids: ['versioning_disabled', 'versioning_check_disabled', 'versioning_check_failed'] },
      { id: '2.1.4', name: 'Ensure S3 bucket server access logging is enabled', check_ids: ['server_access_logging_disabled', 'server_access_logging_check_disabled', 'logging_check_failed'] },
      { id: '4.1', name: 'Ensure no security groups allow unrestricted ingress', check_ids: ['security_group_all_ports_open_to_world', 'security_group_sensitive_port_open_to_world', 'missing_sensitive_ports_config', 'describe_security_groups_failed'] },
      { id: '4.2', name: 'Ensure security groups are only used where necessary', check_ids: ['security_group_unused', 'unused_sg_check_disabled', 'describe_network_interfaces_failed'] },
    ],
  },
  {
    short_name: 'NIST CSF',
    name: 'NIST Cybersecurity Framework',
    controls: [
      { id: 'PR.AC-1', name: 'Identities and credentials are managed', check_ids: ['mfa_not_enabled', 'mfa_check_failed', 'access_key_older_than_threshold', 'root_mfa_not_enabled', 'root_mfa_check_failed'] },
      { id: 'PR.AC-4', name: 'Access permissions are managed', check_ids: ['admin_policy_wildcards_detected', 'policy_allow_not_action', 'policy_allow_not_resource', 'policy_privilege_escalation_action'] },
      { id: 'PR.AC-7', name: 'Users and devices are authenticated', check_ids: ['mfa_not_enabled', 'root_mfa_not_enabled', 'access_key_unused_over_threshold', 'access_key_never_used'] },
      { id: 'PR.DS-1', name: 'Data at rest is protected', check_ids: ['default_encryption_not_configured', 'default_encryption_check_failed', 'default_encryption_algorithm_not_allowed'] },
      { id: 'PR.DS-2', name: 'Data in transit is protected', check_ids: ['s3_public', 'public_access_enabled'] },
      { id: 'PR.IP-1', name: 'A baseline configuration is maintained', check_ids: ['versioning_disabled', 'server_access_logging_disabled'] },
      { id: 'DE.CM-1', name: 'Network is monitored', check_ids: ['security_group_all_ports_open_to_world', 'security_group_sensitive_port_open_to_world'] },
      { id: 'DE.CM-2', name: 'Physical environment is monitored', check_ids: ['security_group_unused'] },
    ],
  },
  {
    short_name: 'ISO 27001',
    name: 'ISO 27001:2022',
    controls: [
      { id: 'A.5.15', name: 'Access control', check_ids: ['mfa_not_enabled', 'root_mfa_not_enabled', 'admin_policy_wildcards_detected'] },
      { id: 'A.5.24', name: 'Use of cryptography', check_ids: ['default_encryption_not_configured', 'default_encryption_algorithm_not_allowed'] },
      { id: 'A.5.25', name: 'Secure development lifecycle', check_ids: ['s3_public', 'public_access_enabled'] },
      { id: 'A.5.28', name: 'Secure disposal of equipment', check_ids: ['versioning_disabled', 'server_access_logging_disabled'] },
      { id: 'A.8.8', name: 'Management of technical vulnerabilities', check_ids: ['security_group_all_ports_open_to_world', 'security_group_sensitive_port_open_to_world'] },
      { id: 'A.8.9', name: 'Configuration management', check_ids: ['access_key_older_than_threshold', 'access_key_unused_over_threshold', 'security_group_unused'] },
    ],
  },
  {
    short_name: 'SOC 2',
    name: 'SOC 2 Type II',
    controls: [
      { id: 'CC6.1', name: 'Logical and physical access controls', check_ids: ['mfa_not_enabled', 'root_mfa_not_enabled', 'admin_policy_wildcards_detected'] },
      { id: 'CC6.6', name: 'Logical access – credentials', check_ids: ['access_key_older_than_threshold', 'access_key_unused_over_threshold', 'access_key_never_used'] },
      { id: 'CC6.7', name: 'Transmission of data', check_ids: ['s3_public', 'public_access_enabled', 'default_encryption_not_configured'] },
      { id: 'CC7.1', name: 'Detection of security events', check_ids: ['server_access_logging_disabled', 'versioning_disabled'] },
      { id: 'CC7.2', name: 'Monitoring of system', check_ids: ['security_group_all_ports_open_to_world', 'security_group_sensitive_port_open_to_world', 'security_group_unused'] },
    ],
  },
] as const;

/** All check_ids that appear in any control (for reference) */
export function getCheckIdsInScope(): Set<string> {
  const set = new Set<string>();
  for (const fw of COMPLIANCE_FRAMEWORK_CONTROLS) {
    for (const ctrl of fw.controls) {
      ctrl.check_ids.forEach((id) => set.add(id));
    }
  }
  return set;
}
