// ============================================================
// Compliance Framework Definitions
// Single source of truth for all compliance frameworks
// ============================================================

export interface ComplianceFrameworkDefinition {
  name: string;
  short_name: string;
  total_controls: number;
}

export const COMPLIANCE_FRAMEWORKS: readonly ComplianceFrameworkDefinition[] = [
  { 
    name: 'CIS AWS Foundations Benchmark', 
    short_name: 'CIS AWS', 
    total_controls: 49 
  },
  { 
    name: 'NIST Cybersecurity Framework', 
    short_name: 'NIST CSF', 
    total_controls: 23 
  },
  { 
    name: 'ISO 27001:2022', 
    short_name: 'ISO 27001', 
    total_controls: 35 
  },
  { 
    name: 'SOC 2 Type II', 
    short_name: 'SOC 2', 
    total_controls: 28 
  },
] as const;

// Total controls across all frameworks
export const TOTAL_COMPLIANCE_CONTROLS = COMPLIANCE_FRAMEWORKS.reduce(
  (sum, f) => sum + f.total_controls, 
  0
);
