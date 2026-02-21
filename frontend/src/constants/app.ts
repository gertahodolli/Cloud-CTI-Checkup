// ============================================================
// Application Identity & Branding
// ============================================================

export const APP_NAME = 'CTI-Checkup';
export const APP_TAGLINE = 'Cloud Security';
export const APP_TITLE = 'CTI-Checkup | Cloud Security Posture';
export const APP_VERSION = '1.0.0';

// ============================================================
// CLI Commands & Examples
// ============================================================

export const CLI_NAME = 'cti-checkup';

export const CLI_COMMANDS = {
  scan: `${CLI_NAME} cloud aws scan --output ./runs/`,
  aiSummarize: `${CLI_NAME} ai summarize cloudtrail --events events.json`,
  exportDetections: `${CLI_NAME} export detections --input scan_result.json --format sigma --out ./exports/`,
} as const;

// ============================================================
// Default Paths
// ============================================================

export const DEFAULT_PATHS = {
  configDir: '~/.cti-checkup/',
  envFile: 'project .env',
  runsDir: '~/.cti-checkup/runs/',
  awsConfig: '~/.aws/config',
  awsCredentials: '~/.aws/credentials',
} as const;

// ============================================================
// Server Configuration
// ============================================================

export const SERVER_CONFIG = {
  defaultPort: 3001,
  startCommand: 'cd frontend/server && npm install && npm start',
} as const;
