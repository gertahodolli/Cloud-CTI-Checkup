const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3001/api';

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || 'Request failed');
  }

  return res.json();
}

// Health check
export async function checkHealth(): Promise<{ status: string; timestamp: string }> {
  return request('/health');
}

// ============ UI Config ============

export interface UIConfig {
  configPath: string;
  runsDirectory: string;
  timezone: string;
  awsProfile: string | null;
  theme: 'dark' | 'light';
}

export async function getUIConfig(): Promise<UIConfig> {
  return request('/config/ui');
}

export async function saveUIConfig(config: UIConfig): Promise<{ success: boolean }> {
  return request('/config/ui', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// ============ YAML Config ============

export interface YAMLConfigResponse {
  path: string;
  content: Record<string, unknown>;
  raw: string;
}

export async function getYAMLConfig(path?: string): Promise<YAMLConfigResponse> {
  const query = path ? `?path=${encodeURIComponent(path)}` : '';
  return request(`/config/yaml${query}`);
}

export async function saveYAMLConfig(path: string, content: Record<string, unknown> | string): Promise<{ success: boolean }> {
  return request('/config/yaml', {
    method: 'POST',
    body: JSON.stringify({ path, content }),
  });
}

export async function validateYAML(content: string): Promise<{ valid: boolean; error?: string }> {
  return request('/config/yaml/validate', {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}

export interface ConfigFile {
  name: string;
  path: string;
}

export async function listConfigFiles(): Promise<{ configDir: string; files: ConfigFile[] }> {
  return request('/config/list');
}

export async function getConfigSchema(): Promise<Record<string, unknown>> {
  return request('/config/schema');
}

// ============ AWS ============

export interface AWSProfile {
  name: string;
  source: 'config' | 'credentials';
  hasConfig?: boolean;
  hasCredentials?: boolean;
}

export interface AWSProfilesResponse {
  profiles: AWSProfile[];
  configPath: string;
  credentialsPath: string;
}

export async function getAWSProfiles(): Promise<AWSProfilesResponse> {
  return request('/aws/profiles');
}

export interface AWSStatus {
  configured: boolean;
  configExists: boolean;
  credentialsExists: boolean;
  configPath: string;
  credentialsPath: string;
}

export async function getAWSStatus(): Promise<AWSStatus> {
  return request('/aws/status');
}

export interface AWSRegion {
  code: string;
  name: string;
}

export async function getAWSRegions(): Promise<{ regions: AWSRegion[] }> {
  return request('/aws/regions');
}

// ============ Secrets ============

export interface SecretStatus {
  configured: boolean;
  masked: string | null;
  source?: 'project' | 'user' | 'env';
}

export interface SecretsStatusResponse {
  envPath: string;
  projectEnvPath?: string;
  secrets: Record<string, SecretStatus>;
}

export async function getSecretsStatus(): Promise<SecretsStatusResponse> {
  return request('/secrets/status');
}

export interface SetSecretResponse {
  success: boolean;
  configured: boolean;
  envPath?: string;
  projectEnvPath?: string;
  userEnvPath?: string;
  secrets?: Record<string, SecretStatus>;
}

export async function setSecret(key: string, value: string): Promise<SetSecretResponse> {
  return request('/secrets/set', {
    method: 'POST',
    body: JSON.stringify({ key, value }),
  });
}

export async function deleteSecret(key: string): Promise<{ success: boolean }> {
  return request(`/secrets/${encodeURIComponent(key)}`, {
    method: 'DELETE',
  });
}

export interface SecretKey {
  key: string;
  label: string;
  provider: string;
}

export async function getSecretKeys(): Promise<{ keys: SecretKey[] }> {
  return request('/secrets/keys');
}

// ============ Runs ============

export interface RunSummary {
  provider: string;
  account_id?: string;
  regions: string[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    skipped: number;
    errors: number;
  };
  risk_score?: number;
  findings_count: number;
  cloudtrail_mode?: 'baseline' | 'llm' | null;
}

export interface Run {
  id: string;
  path: string;
  created: string;
  modified: string;
  name?: string | null;
  summary: RunSummary | null;
}

export interface RunsResponse {
  runsDir: string;
  runs: Run[];
}

export async function getRuns(): Promise<RunsResponse> {
  return request('/runs');
}

export async function getRun(id: string): Promise<{ id: string; path: string; files: Record<string, unknown> }> {
  return request(`/runs/${id}`);
}

export async function updateRunName(runId: string, name: string): Promise<{ success: boolean; name: string }> {
  return request(`/runs/${runId}`, {
    method: 'PATCH',
    body: JSON.stringify({ name }),
  });
}

export async function deleteRun(runId: string): Promise<{ success: boolean }> {
  return request(`/runs/${encodeURIComponent(runId)}`, { method: 'DELETE' });
}

export async function getScanResult(runId: string): Promise<unknown> {
  return request(`/runs/${runId}/scan`);
}

export async function getAISummary(runId: string): Promise<unknown> {
  return request(`/runs/${runId}/ai-summary`);
}

// ============ Indicators (IOCs) ============

export interface ExtractedIndicators {
  ips: string[];
  ips_count: number;
  access_key_ids: string[];
  access_key_ids_count: number;
  identities: string[];
  identities_count: number;
  user_agents: string[];
  user_agents_count: number;
  domains: string[];
  domains_count: number;
  event_sources: string[];
  regions: string[];
}

export interface IndicatorsResponse {
  runId: string;
  hasIndicators: boolean;
  indicators: ExtractedIndicators;
}

export async function getIndicators(runId: string): Promise<IndicatorsResponse> {
  return request(`/runs/${runId}/indicators`);
}

export interface ExportFile {
  name: string;
  path: string;
  size: number;
  format: string;
}

export async function getExports(runId: string): Promise<{ exports: ExportFile[] }> {
  return request(`/runs/${runId}/exports`);
}

export function getExportDownloadUrl(runId: string, filename: string): string {
  return `${API_BASE}/runs/${runId}/exports/${filename}`;
}

// ============ Scan Execution ============

export interface StartScanRequest {
  provider?: 'aws';
  regions?: string[];
  profile?: string;
  configPath?: string;
  checks?: string[];
}

export interface StartScanResponse {
  success: boolean;
  runId: string;
  outputDir: string;
  args: string[];
  status: string;
  message: string;
}

export async function startScan(options?: StartScanRequest): Promise<StartScanResponse> {
  return request('/runs/start', {
    method: 'POST',
    body: JSON.stringify(options || {}),
  });
}

export interface ActiveScan {
  id: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled' | 'error';
  startedAt: string;
  endedAt: string | null;
  exitCode: number | null;
  outputLines: number;
  errorLines: number;
}

export interface ActiveScansResponse {
  scans: ActiveScan[];
}

export async function getActiveScans(): Promise<ActiveScansResponse> {
  return request('/runs/active');
}

export interface ActiveScanDetail extends ActiveScan {
  output: string[];
  errors: string[];
  args: string[];
  pid: number;
}

export async function getActiveScanStatus(runId: string): Promise<ActiveScanDetail> {
  return request(`/runs/active/${runId}`);
}

export async function cancelScan(runId: string): Promise<{ success: boolean; message: string }> {
  return request(`/runs/active/${runId}/cancel`, {
    method: 'POST',
  });
}

// ============ CloudTrail Analysis ============

export interface StartCloudTrailRequest {
  eventsContent: string;
  mode?: 'baseline' | 'llm';
  configPath?: string;
}

export interface StartCloudTrailResponse {
  success: boolean;
  runId: string;
  outputDir: string;
  args: string[];
  status: string;
  message: string;
}

export async function startCloudTrailAnalysis(options: StartCloudTrailRequest): Promise<StartCloudTrailResponse> {
  return request('/runs/start-cloudtrail', {
    method: 'POST',
    body: JSON.stringify(options),
  });
}

// ============ Threat Intelligence ============

export interface IntelIPResult {
  success: boolean;
  ip: string;
  result: unknown;
  raw: string;
}

export async function checkIP(ip: string): Promise<IntelIPResult> {
  return request('/intel/ip', {
    method: 'POST',
    body: JSON.stringify({ ip, format: 'json' }),
  });
}

export interface IntelBatchIPResult {
  success: boolean;
  total: number;
  successful: number;
  failed: number;
  results: Array<{
    ip: string;
    success: boolean;
    result?: unknown;
    error?: string;
  }>;
}

export async function checkIPBatch(ips: string[]): Promise<IntelBatchIPResult> {
  return request('/intel/ip/batch', {
    method: 'POST',
    body: JSON.stringify({ ips, format: 'json' }),
  });
}

export interface IntelDomainResult {
  success: boolean;
  domain: string;
  result: unknown;
  raw: string;
}

export async function checkDomain(domain: string): Promise<IntelDomainResult> {
  return request('/intel/domain', {
    method: 'POST',
    body: JSON.stringify({ domain, format: 'json' }),
  });
}

export interface IntelHashResult {
  success: boolean;
  hash: string;
  result: unknown;
  raw: string;
}

export async function checkHash(hash: string): Promise<IntelHashResult> {
  return request('/intel/hash', {
    method: 'POST',
    body: JSON.stringify({ hash, format: 'json' }),
  });
}
