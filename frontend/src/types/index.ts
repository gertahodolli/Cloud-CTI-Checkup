// Types based on cti_checkup models

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Status = 'ok' | 'finding' | 'skipped' | 'error';
export type FindingStatus = 'open' | 'resolved' | 'suppressed';

export interface Finding {
  finding_id: string;
  service: string;
  region?: string;
  resource_type: string;
  resource_id: string;
  issue: string;
  severity: Severity;
  status: Status;
  finding_status: FindingStatus;
  evidence: Record<string, any>;
  remediation?: string;
  first_seen: string;
  ai_explanation?: string;
  has_detection?: boolean;
}

export interface CheckRun {
  name: string;
  status: Status;
  message?: string;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  skipped: number;
  errors: number;
}

export interface ScanResult {
  provider: string;
  account_id?: string;
  regions: string[];
  checks: CheckRun[];
  findings: Finding[];
  summary: Summary;
  partial_failure: boolean;
  fatal_error: boolean;
  risk_score?: number;
  risk_score_explanation?: Record<string, any>;
  scan_date: string;
}

export interface ComplianceFramework {
  name: string;
  short_name: string;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  percentage: number;
}

export interface TimelineItem {
  /** Frontend/convention field */
  timestamp?: string;
  /** Backend sends `time` (CloudTrail AI/baseline) */
  time?: string;
  event: string;
  actor?: string;
  severity?: Severity;
}

export interface TopActor {
  identity: string;
  identity_type: string;
  event_count: number;
  risk_level: Severity;
  notable_actions: string[];
}

export interface RecommendedDetection {
  name: string;
  type: 'sigma' | 'kql' | 'splunk' | 'cloudwatch';
  description: string;
  available: boolean;
}

export interface CloudTrailAISummary {
  type: string;
  summary_text: string;
  key_observations: string[];
  timeline: TimelineItem[];
  top_actors: TopActor[];
  recommended_actions: string[];
  recommended_detections: RecommendedDetection[];
  confidence: number;
  limitations: string[];
  errors: string[];
  affected_services: string[];
}

export interface TrendDataPoint {
  date: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Report {
  id: string;
  name: string;
  type: 'aws_scan' | 'cloudtrail_incident' | 'iam_risk';
  created_at: string;
  formats: ('json' | 'sigma' | 'kql' | 'cloudwatch' | 'splunk')[];
}

// Navigation
export interface NavItem {
  id: string;
  label: string;
  icon: string;
  path: string;
  badge?: number;
}
