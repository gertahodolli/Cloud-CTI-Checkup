/**
 * Shared compliance calculation from findings.
 * Maps scan finding issues to framework controls (CIS AWS, NIST CSF, etc.).
 */
import type { Finding, ComplianceFramework } from '../types';
import { COMPLIANCE_FRAMEWORK_CONTROLS, type ComplianceControl } from '../constants/complianceMappings';

function getCheckId(f: Finding): string {
  return (f.issue ?? (f as unknown as { finding_id?: string }).finding_id ?? '').trim();
}

export interface ControlResult {
  control: ComplianceControl;
  passed: boolean;
  violatingFindings: Finding[];
}

export interface FrameworkWithControls extends ComplianceFramework {
  controlResults: ControlResult[];
}

export function calculateComplianceWithControls(findings: Finding[]): FrameworkWithControls[] {
  const findingsByIssue = new Map<string, Finding[]>();
  for (const f of findings) {
    const id = getCheckId(f);
    if (id) {
      const list = findingsByIssue.get(id) ?? [];
      list.push(f);
      findingsByIssue.set(id, list);
    }
  }

  return COMPLIANCE_FRAMEWORK_CONTROLS.map((framework) => {
    const controlResults: ControlResult[] = [];
    for (const control of framework.controls) {
      const violatingFindings: Finding[] = [];
      for (const cid of control.check_ids) {
        const list = findingsByIssue.get(cid) ?? [];
        violatingFindings.push(...list);
      }
      const passed = violatingFindings.length === 0;
      controlResults.push({ control, passed, violatingFindings });
    }
    const passed = controlResults.filter((r) => r.passed).length;
    const total = framework.controls.length;
    const failed = total - passed;
    const percentage = total > 0 ? Math.round((passed / total) * 100) : 0;

    return {
      name: framework.name,
      short_name: framework.short_name,
      total_controls: total,
      passed_controls: passed,
      failed_controls: failed,
      percentage,
      controlResults,
    };
  });
}
