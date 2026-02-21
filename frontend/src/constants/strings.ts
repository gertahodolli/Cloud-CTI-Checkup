// ============================================================
// UI Strings - Single source of truth for all user-facing text
// Organized by feature/page for easy maintenance
// ============================================================

import { APP_NAME, APP_TAGLINE, CLI_COMMANDS, DEFAULT_PATHS, SERVER_CONFIG } from './app';

// ============================================================
// Global / Layout
// ============================================================

export const STRINGS = {
  // App identity (derived from app.ts)
  app: {
    name: APP_NAME,
    tagline: APP_TAGLINE,
  },

  // Loading states
  loading: {
    default: 'Loading...',
    connecting: 'Connecting to server...',
    fetchingData: 'Fetching data...',
  },

  // Server connection
  server: {
    notConnected: 'Server not connected',
    notConnectedHint: `Start the backend server: ${SERVER_CONFIG.startCommand}`,
    reconnecting: 'Reconnecting...',
  },

  // Navigation labels
  nav: {
    dashboard: 'Dashboard',
    findings: 'Findings',
    assets: 'Assets',
    compliance: 'Compliance',
    aiInsights: 'AI Insights',
    cloudtrail: 'CloudTrail',
    intel: 'Threat Intel',
    indicators: 'IOCs',
    alerts: 'Alerts',
    reports: 'Reports',
    settings: 'Settings',
  },

  // Common actions
  actions: {
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    download: 'Download',
    refresh: 'Refresh',
    search: 'Search',
    filter: 'Filter',
    apply: 'Apply',
    reset: 'Reset',
    configure: 'Configure',
    validate: 'Validate',
  },

  // Common labels
  common: {
    severity: 'Severity',
    status: 'Status',
    service: 'Service',
    region: 'Region',
    resource: 'Resource',
    all: 'All',
    none: 'None',
    yes: 'Yes',
    no: 'No',
    enabled: 'Enabled',
    disabled: 'Disabled',
    configured: 'Configured',
    notConfigured: 'Not configured',
    available: 'Available',
    notAvailable: 'Not available',
  },

  // Time-related
  time: {
    justNow: 'Just now',
    hoursAgo: (n: number) => `${n} hour${n === 1 ? '' : 's'} ago`,
    daysAgo: (n: number) => `${n} day${n === 1 ? '' : 's'} ago`,
    lastScan: 'Last scan',
    noDate: 'No date available',
  },

  // ============================================================
  // Dashboard Page
  // ============================================================
  dashboard: {
    title: 'Security Dashboard',
    noScanData: 'No Scan Data',
    noScanDataHint: 'Run a scan to see results here.',
    runScanHint: `Run: ${CLI_COMMANDS.scan}`,
    lastScanPrefix: 'Last scan:',
    accountPrefix: 'Account:',
  },

  // ============================================================
  // Findings Page
  // ============================================================
  findings: {
    title: 'Findings',
    searchPlaceholder: 'Search findings...',
    filtersTitle: 'Filters',
    severityFilter: 'Severity',
    serviceFilter: 'Service',
    statusFilter: 'Status',
    detectionFilter: 'Detection Coverage',
    hasDetection: 'Has detection',
    countLabel: (filtered: number, total: number) => `${filtered} of ${total} findings`,
    noFindings: 'No findings in this scan',
    noMatchingFindings: 'No findings match your filters',
    selectRunHint: 'Select a run to view findings.',
    // Finding detail panel
    detail: {
      aiExplanation: 'AI-assisted summary (based on evidence)',
      recommendedActions: 'Recommended Actions',
      evidence: 'Evidence',
      detectionCoverage: 'Detection Coverage',
      sigmaRule: 'Sigma rule',
      firstSeen: 'First Seen',
      findingId: 'Finding ID',
    },
  },

  // ============================================================
  // AI Insights Page
  // ============================================================
  aiInsights: {
    title: 'AI Insights',
    subtitle: 'CloudTrail incident analysis and recommendations',
    noSummary: 'No AI Summary Available',
    noSummaryHint: 'This run does not have an AI summary. Generate one using the CLI:',
    selectRunHint: 'Select a run to view AI insights.',
    baselineRun: 'Baseline analysis (no AI)',
    baselineRunHint: 'This run used baseline (deterministic) mode. For AI-powered insights, re-run the CloudTrail analysis with AI mode from the CloudTrail page.',
    cliCommand: CLI_COMMANDS.aiSummarize,
    // Sections
    incidentOverview: 'Incident Overview',
    confidence: 'Confidence',
    analysisLimitations: 'Analysis Limitations',
    eventTimeline: 'Event Timeline',
    keyActors: 'Key Actors',
    affectedServices: 'Affected Services',
    keyObservations: 'Key Observations',
    recommendedActions: 'Recommended Actions',
    recommendedDetections: 'Recommended Detections',
    noTimelineEvents: 'No timeline events',
    noActorsIdentified: 'No actors identified',
  },

  // ============================================================
  // Reports Page
  // ============================================================
  reports: {
    title: 'Reports & Export',
    subtitle: 'Download scan reports and detection rules',
    exportFormats: 'Export Formats',
    exportFormatsHint: 'Detection rules can be exported using the CLI',
    cliCommand: CLI_COMMANDS.exportDetections,
    availableExports: 'Available Exports',
    fromSelectedRun: 'from selected run',
    noExports: 'No exports available for this run',
    selectRunHint: 'Select a run to view exports',
    recentRuns: 'Recent Runs',
    noRuns: 'No runs available',
    // Export format labels
    formats: {
      json: { label: 'JSON', description: 'Raw data export' },
      sigma: { label: 'Sigma', description: 'Detection rules' },
      kql: { label: 'KQL', description: 'Azure Sentinel' },
      cloudwatch: { label: 'CloudWatch', description: 'AWS alerts' },
      splunk: { label: 'Splunk', description: 'Splunk queries' },
    },
  },

  // ============================================================
  // Alerts Page
  // ============================================================
  alerts: {
    title: 'Alerts',
    subtitle: (count: number) => `${count} critical and high severity findings`,
    allSeverities: 'All severities',
    noAlerts: 'No Alerts',
    noAlertsHint: 'No critical or high severity findings in this scan',
    selectRunHint: 'Select a run to view alerts',
    criticalFinding: 'Critical finding detected',
    highFinding: 'High finding detected',
  },

  // ============================================================
  // Assets Page
  // ============================================================
  assets: {
    title: 'Assets',
    subtitle: (assets: number, findings: number) => 
      assets > 0 
        ? `${assets} resources with findings • ${findings} total findings`
        : 'No assets discovered in this scan',
    resourcesWithFindings: 'Resources with Findings',
    totalFindings: 'Total Findings',
    regions: 'Regions',
    services: 'Services',
    noAssets: 'No Assets Found',
    noAssetsHint: 'No resources with findings in this scan',
    selectRunHint: 'Select a run to view assets',
    findingsByRegion: 'Findings by Region',
    findingsLabel: (n: number) => `${n} findings`,
    resourcesLabel: (n: number) => `${n} resources`,
  },

  // ============================================================
  // Compliance Page
  // ============================================================
  compliance: {
    title: 'Compliance',
    subtitle: 'Security framework compliance status',
    overallCompliance: 'Overall Compliance',
    acrossAllFrameworks: 'Across all frameworks',
    controlsLabel: (passed: number, total: number) => `${passed} of ${total} controls`,
    passed: 'passed',
    failed: 'failed',
    totalControls: 'total controls',
    selectRunHint: 'Select a run with findings to see compliance calculations',
    disclaimer: 'Compliance percentages are estimates based on scan findings. For accurate compliance assessments, map findings to specific control requirements.',
  },

  // ============================================================
  // Settings Page
  // ============================================================
  settings: {
    title: 'Settings',
    // Tab labels
    tabs: {
      general: 'General',
      aws: 'AWS',
      ai: 'AI / LLM',
      apikeys: 'API Keys',
      export: 'Detection Export',
      paths: 'Paths & Storage',
      advanced: 'Advanced',
    },
    // General tab
    general: {
      title: 'General Settings',
      timezone: 'Timezone',
      timezoneHint: 'Used for displaying dates and times',
      theme: 'Theme',
      themeHint: 'UI color scheme',
    },
    // AWS tab
    aws: {
      title: 'AWS Configuration',
      profile: 'AWS Profile',
      profileHint: 'Select an AWS profile from your local configuration',
      noProfiles: 'No AWS profiles found',
      profilesFrom: 'Profiles loaded from',
      regions: 'Regions',
      regionsHint: 'Select regions to scan',
      services: 'Services',
      servicesHint: 'Toggle services to include in scans',
      configPathHint: 'AWS credentials are loaded from ~/.aws in your home directory.',
      notConfiguredHint: 'Run "aws configure" to set up your AWS credentials, or set AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE environment variables to specify custom paths.',
    },
    // AI tab
    ai: {
      title: 'AI / LLM Settings',
      provider: 'AI Provider',
      providerHint: 'Select your preferred AI provider',
      apiKey: 'API Key',
      apiKeyPlaceholder: 'Enter API key...',
      apiKeyHint: (path: string) => `Stored securely in ${path}`,
      apiKeyConfigured: 'API key configured',
      apiKeyNotConfigured: 'API key not configured',
      model: 'Model',
      modelHint: 'Select the model to use',
      validate: 'Validate Connection',
    },
    // API Keys tab
    apikeys: {
      title: 'API Keys',
      description: 'Manage API keys for threat intelligence lookups and AI features',
      storedIn: 'Keys are stored in',
    },
    // Export tab
    export: {
      title: 'Detection Export Settings',
      enabledFormats: 'Enabled Export Formats',
      formatHint: 'Select which detection formats to generate',
    },
    // Paths tab
    paths: {
      title: 'Paths & Storage',
      configFile: 'Configuration File',
      configFileHint: 'Main CTI-Checkup configuration file',
      runsDirectory: 'Runs Directory',
      runsDirectoryHint: 'Directory where scan results are stored',
    },
    // Advanced tab
    advanced: {
      title: 'Advanced Configuration',
      yamlEditor: 'YAML Configuration',
      yamlEditorHint: 'Edit the raw configuration file',
      validYaml: 'Valid YAML',
      invalidYaml: 'Invalid YAML',
    },
  },

  // ============================================================
  // Threat Intel Page
  // ============================================================
  intel: {
    title: 'Threat Intelligence',
    subtitle: 'Look up IPs, domains, and hashes against threat intelligence feeds',
    // Tabs
    tabs: {
      ip: 'IP Address',
      domain: 'Domain',
      hash: 'File Hash',
      batch: 'Batch Lookup',
    },
    // IP lookup
    ip: {
      title: 'IP Address Lookup',
      placeholder: 'Enter IP address (e.g., 8.8.8.8)',
      lookupButton: 'Check IP',
      lookupHint: 'Query threat intelligence feeds for information about this IP',
      invalidIP: 'Invalid IP address format',
    },
    // Domain lookup
    domain: {
      title: 'Domain Lookup',
      placeholder: 'Enter domain (e.g., example.com)',
      lookupButton: 'Check Domain',
      lookupHint: 'Query threat intelligence feeds for information about this domain',
      invalidDomain: 'Invalid domain format',
    },
    // Hash lookup
    hash: {
      title: 'File Hash Lookup',
      placeholder: 'Enter MD5, SHA1, or SHA256 hash',
      lookupButton: 'Check Hash',
      lookupHint: 'Query threat intelligence feeds for file hash information',
      invalidHash: 'Invalid hash format (must be MD5, SHA1, or SHA256)',
    },
    // Batch lookup
    batch: {
      title: 'Batch IP Lookup',
      placeholder: 'Enter IP addresses (one per line, max 100)',
      lookupButton: 'Check All IPs',
      lookupHint: 'Look up multiple IP addresses at once',
    },
    // Results
    results: {
      title: 'Results',
      noResults: 'No results yet',
      noResultsHint: 'Enter a value and click lookup to see results',
      loading: 'Looking up...',
      error: 'Lookup failed',
      errorHint: 'Make sure cti-checkup is installed and in your PATH',
      threatScore: 'Threat Score',
      reputation: 'Reputation',
      categories: 'Categories',
      country: 'Country',
      asn: 'ASN',
      rawData: 'Raw Data',
      riskScore: 'Risk score',
      riskScoreOutOf: (score: number, cap: number) => `${score} / ${cap}`,
      findingsSummary: 'Findings',
      findingsCounts: (critical: number, high: number, medium: number, low: number, info: number) => {
        const parts: string[] = [];
        if (critical > 0) parts.push(`${critical} critical`);
        parts.push(`${high} high`, `${medium} medium`, `${low} low`, `${info} info`);
        return parts.join(', ');
      },
      noFindings: 'No findings',
      remediation: 'Remediation',
      evidence: 'Evidence',
      resource: 'Resource',
      issue: 'Issue',
      showRawJson: 'Show raw JSON',
      hideRawJson: 'Hide raw JSON',
      partialFailure: 'Some checks failed',
      fatalError: 'Lookup failed with an error',
      // VirusTotal-specific
      vtVendorsFlagged: (malicious: number, total: number) => 
        malicious > 0 
          ? `${malicious}/${total} security vendors flagged this as malicious`
          : `No security vendors flagged this as malicious`,
      vtDetectionRatio: 'Detection ratio',
      vtLastAnalysis: 'Last analysis',
      vtCommunityScore: 'Community score',
      vtCheckAgain: 'Check again',
      vtDaysAgo: (days: number) => days === 1 ? '1 day ago' : `${days} days ago`,
      vtMonthsAgo: (months: number) => months === 1 ? '1 month ago' : `${months} months ago`,
      vtYearsAgo: (years: number) => years === 1 ? '1 year ago' : `${years} years ago`,
      vtJustNow: 'Just now',
    },
  },

  // ============================================================
  // Scan Execution
  // ============================================================
  scan: {
    startScan: 'Start Scan',
    startingScan: 'Starting...',
    scanRunning: 'Scan running',
    scanCompleted: 'Scan completed',
    scanFailed: 'Scan failed',
    scanCancelled: 'Scan cancelled',
    cancelScan: 'Cancel Scan',
    viewOutput: 'View Output',
    noActiveScans: 'No active scans',
    // Modal
    modal: {
      title: 'Start New Scan',
      subtitle: 'Configure and run a new AWS security scan',
      profile: 'AWS Profile',
      profileHint: 'Leave empty to use default profile',
      regions: 'Regions',
      regionsHint: 'Leave empty to use all configured regions',
      start: 'Start Scan',
      cancel: 'Cancel',
    },
    // Status
    status: {
      running: 'Running',
      completed: 'Completed',
      failed: 'Failed',
      cancelled: 'Cancelled',
      error: 'Error',
    },
  },

  // ============================================================
  // TopBar
  // ============================================================
  topBar: {
    searchPlaceholder: 'Search findings, assets, policies...',
    runSelector: {
      label: 'Select Run',
      noRuns: 'No runs available',
      recentRuns: 'Recent runs',
      newScan: 'New scan',
      deleteScan: 'Delete scan',
    },
    notifications: 'Notifications',
  },

  // ============================================================
  // Empty States
  // ============================================================
  empty: {
    noRunSelected: 'No Run Selected',
    selectRunGeneric: 'Select a run from the dropdown to view data.',
    serverNotConnected: 'Server Not Connected',
    startServerHint: 'Start the backend server to continue.',
  },

  // ============================================================
  // Error States
  // ============================================================
  errors: {
    loadFailed: 'Failed to load data',
    saveFailed: 'Failed to save',
    connectionFailed: 'Connection failed',
    invalidInput: 'Invalid input',
    tryAgain: 'Please try again',
  },

  // ============================================================
  // CloudTrail Analysis
  // ============================================================
  cloudtrail: {
    title: 'CloudTrail Analysis',
    subtitle: 'Analyze AWS CloudTrail events to extract IOCs (IPs, identities, access keys) and generate security insights',
    
    upload: {
      title: 'Upload CloudTrail Events',
      dropzoneText: 'Drop your CloudTrail events file here, or click to browse',
      dropzoneHint: 'Supports JSON arrays, Records objects, and JSONL format',
      removeFile: 'Remove file',
    },
    
    options: {
      title: 'Analysis Options',
      modeLabel: 'Analysis Mode',
      baseline: {
        name: 'Baseline (No AI)',
        description: 'Deterministic analysis using regex patterns. Fast, reliable, no API keys required.',
      },
      llm: {
        name: 'AI-Powered',
        description: 'Uses LLM for intelligent summarization. Requires AI provider configured in settings.',
      },
    },
    
    actions: {
      startAnalysis: 'Start Analysis',
      analyzing: 'Analyzing...',
    },
    
    info: {
      title: 'How it works',
      steps: [
        'Upload your CloudTrail events file (JSON array, Records object, or JSONL)',
        'Choose analysis mode: Baseline (no AI) or AI-powered',
        'View extracted IOCs (IPs, identities, access keys) in the IOCs page',
      ],
      analyzingHint: 'This may take a few moments depending on the file size...',
    },
    
    cliHint: {
      label: 'Or use the CLI:',
      command: 'cti-checkup ai summarize cloudtrail --events <file> --mode baseline',
    },
    
    errors: {
      invalidFileType: 'Please select a JSON or JSONL file containing CloudTrail events',
      invalidJsonFormat: 'Invalid JSON format. File must be a JSON array, Records object, or JSONL',
      invalidStructure: 'CloudTrail file must be a JSON array of events or have a "Records" field',
      readFailed: 'Failed to read file',
      analysisFailed: 'Analysis failed',
      unknownError: 'Unknown error',
      timeout: 'Analysis timed out. Check the run manually.',
      startFailed: 'Failed to start analysis',
    },
    
    success: {
      runIdLabel: 'Run ID',
    },
  },

  // ============================================================
  // IOCs / Indicators
  // ============================================================
  indicators: {
    title: 'Extracted Indicators (IOCs)',
    subtitle: 'Deterministic extraction of IPs, identities, and access keys from CloudTrail events',
    subtitleShort: 'Deterministic extraction from CloudTrail events using regex and field parsing',
    
    noRunSelected: {
      title: 'No Run Selected',
      description: 'Select a run with CloudTrail analysis to view extracted indicators.',
    },
    
    noIndicators: {
      title: 'No Indicators Available',
      description: "This run doesn't have extracted indicators. Run a CloudTrail analysis to extract IOCs:",
      cliCommand: 'cti-checkup ai summarize cloudtrail --events events.json',
    },
    
    sections: {
      ips: 'IP Addresses',
      accessKeys: 'Access Key IDs',
      identities: 'Identities',
      domains: 'Domains',
      metadata: 'Metadata',
    },
    
    stats: {
      ips: 'IPs',
      accessKeys: 'Access Keys',
      identities: 'Identities',
      regions: 'Regions',
    },
    
    actions: {
      copyAll: 'Copy All',
      copied: 'Copied!',
      useInThreatIntel: 'Use in Threat Intel',
    },
    
    hints: {
      ipsCopy: 'Tip: Copy IPs and paste into Threat Intel → Batch Lookup for reputation checks',
      keysMasked: 'Keys are masked (last 4 chars shown). For key age and rotation status, run an AWS scan and check IAM findings.',
      identitiesInfo: 'Includes ARNs, usernames, principal IDs, and assumed roles from CloudTrail events',
      regionsLabel: 'Regions',
      eventSourcesLabel: 'Event Sources',
      userAgentsLabel: 'Unique User Agents',
    },
    
    nextSteps: {
      title: 'Next Steps',
      items: [
        'Copy IPs and run them through Threat Intel → Batch Lookup for reputation checks',
        'For long-lived access keys and key age: run an AWS scan and check IAM findings',
        'Review identities for unexpected users, roles, or cross-account access',
      ],
      awsScanCommand: 'cti-checkup cloud aws scan',
    },
    
    empty: {
      ips: 'No external IPs found in events',
      accessKeys: 'No access key IDs found in events',
      identities: 'No identities found in events',
    },
  },
} as const;

// Export individual sections for convenience
export const { 
  app, loading, server, nav, actions, common, time,
  dashboard, findings, aiInsights, reports, alerts, assets, compliance, settings,
  intel, scan, topBar, empty, errors, cloudtrail, indicators
} = STRINGS;
