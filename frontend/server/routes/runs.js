import { Router } from 'express';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { getSpawnEnv } from '../lib/env.js';
import { normalizePathForRuntime } from '../lib/paths.js';

export const runsRouter = Router();

// Get project root for default config path
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..', '..', '..');
const defaultConfigPath = path.join(projectRoot, 'config', 'local.yaml');
const aiConfigPath = path.join(projectRoot, 'config', 'ai.local.yaml');

// =============================================================================
// Configurable defaults
// =============================================================================

/** Time (ms) to keep completed scans in memory before cleanup. Default: 1 hour */
const DEFAULTS = {
  SCAN_CLEANUP_TIMEOUT_MS: 60 * 60 * 1000,  // 1 hour
  CLI_COMMAND: 'cti-checkup',
};

// Track active scans
const activeScans = new Map();

// Get runs directory
const getRunsDir = async () => {
  // Try to read from UI config first
  try {
    const uiConfigPath = path.join(os.homedir(), '.cti-checkup', 'ui_config.json');
    const content = await fs.readFile(uiConfigPath, 'utf-8');
    const config = JSON.parse(content);
    if (config.runsDirectory) {
      return normalizePathForRuntime(config.runsDirectory);
    }
  } catch (err) {
    // Ignore, use default
  }
  
  return path.join(os.homedir(), '.cti-checkup', 'runs');
};

// List all runs
runsRouter.get('/', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    
    try {
      await fs.access(runsDir);
    } catch {
      // Directory doesn't exist yet
      return res.json({ runsDir, runs: [] });
    }
    
    const entries = await fs.readdir(runsDir, { withFileTypes: true });
    
    const runs = [];
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const runPath = path.join(runsDir, entry.name);
        const stat = await fs.stat(runPath);
        
        // Try to read run name and metadata
        let name = null;
        let meta = null;
        try {
          const metaPath = path.join(runPath, 'run_metadata.json');
          const metaContent = await fs.readFile(metaPath, 'utf-8');
          meta = JSON.parse(metaContent);
          if (meta.name && typeof meta.name === 'string' && meta.name.trim()) {
            name = meta.name.trim();
          }
        } catch {
          // No metadata or invalid
        }

        // Try to read summary from the run
        let summary = null;
        try {
          const scanResultPath = path.join(runPath, 'scan_result.json');
          const content = await fs.readFile(scanResultPath, 'utf-8');
          const data = JSON.parse(content);
          summary = {
            provider: data.provider,
            account_id: data.account_id,
            regions: data.regions,
            summary: data.summary,
            risk_score: data.risk_score,
            findings_count: data.findings?.length || 0
          };
        } catch {
          // No scan result - try CloudTrail (has cloudtrail_ai_summary.json but no scan_result.json)
          try {
            const ctPath = path.join(runPath, 'cloudtrail_ai_summary.json');
            await fs.access(ctPath);
            const cloudtrailMode = (meta && (meta.cloudtrail_mode === 'baseline' || meta.cloudtrail_mode === 'llm')) ? meta.cloudtrail_mode : null;
            summary = {
              provider: 'cloudtrail',
              account_id: null,
              regions: [],
              summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, skipped: 0, errors: 0 },
              risk_score: 0,
              findings_count: 0,
              cloudtrail_mode: cloudtrailMode
            };
          } catch {
            // Neither scan_result nor cloudtrail summary found
          }
        }
        
        runs.push({
          id: entry.name,
          path: runPath,
          created: stat.birthtime || stat.mtime,
          modified: stat.mtime,
          name,
          summary
        });
      }
    }
    
    // Sort by created date, newest first
    runs.sort((a, b) => new Date(b.created) - new Date(a.created));
    
    res.json({ runsDir, runs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get a specific run
runsRouter.get('/:id', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const runPath = path.join(runsDir, req.params.id);
    
    // Security: ensure the path is within runsDir
    if (!runPath.startsWith(runsDir)) {
      return res.status(400).json({ error: 'Invalid run ID' });
    }
    
    const entries = await fs.readdir(runPath);
    
    const files = {};
    for (const file of entries) {
      if (file.endsWith('.json')) {
        const filePath = path.join(runPath, file);
        const content = await fs.readFile(filePath, 'utf-8');
        files[file] = JSON.parse(content);
      }
    }
    
    res.json({
      id: req.params.id,
      path: runPath,
      files
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'Run not found' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Update run name (PATCH)
runsRouter.patch('/:id', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const runId = decodeURIComponent(req.params.id || '');
    const runPath = path.join(runsDir, runId);
    const metaPath = path.join(runPath, 'run_metadata.json');

    // Security: ensure runPath is inside runsDir (resolve for consistent path format on Windows)
    const resolvedRunsDir = path.resolve(runsDir);
    const resolvedRunPath = path.resolve(runPath);
    const mustStart = resolvedRunsDir + path.sep;
    if (resolvedRunPath !== resolvedRunsDir && !resolvedRunPath.startsWith(mustStart)) {
      return res.status(400).json({ error: 'Invalid run ID' });
    }

    try {
      await fs.access(runPath);
    } catch {
      return res.status(404).json({ error: 'Run not found' });
    }

    const { name } = req.body;
    if (typeof name !== 'string') {
      return res.status(400).json({ error: 'name must be a string' });
    }

    let meta = {};
    try {
      const content = await fs.readFile(metaPath, 'utf-8');
      meta = JSON.parse(content);
    } catch {
      // File doesn't exist or invalid, start fresh
    }

    meta.name = name.trim();
    await fs.mkdir(runPath, { recursive: true });
    await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf-8');

    res.json({ success: true, name: meta.name });
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'Run not found' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Delete a run (removes the run directory and all its contents)
runsRouter.delete('/:id', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const runId = decodeURIComponent(req.params.id || '');
    const runPath = path.join(runsDir, runId);

    // Security: ensure runPath is inside runsDir (resolve to handle .. and symlinks)
    const resolvedRunsDir = path.resolve(runsDir);
    const resolvedRunPath = path.resolve(runPath);
    const mustStart = resolvedRunsDir + path.sep;
    if (resolvedRunPath !== resolvedRunsDir && !resolvedRunPath.startsWith(mustStart)) {
      return res.status(400).json({ error: 'Invalid run ID' });
    }

    try {
      await fs.access(runPath);
    } catch (accessErr) {
      return res.status(404).json({ error: 'Run not found' });
    }

    await fs.rm(runPath, { recursive: true, force: true });
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'Run not found' });
    }
    return res.status(500).json({ error: err.message });
  }
});

// Get scan result from a run
runsRouter.get('/:id/scan', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const runPath = path.join(runsDir, req.params.id);
    const scanPath = path.join(runPath, 'scan_result.json');
    const cloudtrailSummaryPath = path.join(runPath, 'cloudtrail_ai_summary.json');

    try {
      const content = await fs.readFile(scanPath, 'utf-8');
      const data = JSON.parse(content);

      if (!data.scan_date) {
        try {
          const stat = await fs.stat(runPath);
          data.scan_date = (stat.birthtime || stat.mtime).toISOString();
        } catch {
          data.scan_date = new Date().toISOString();
        }
      }

      return res.json(data);
    } catch (scanErr) {
      if (scanErr.code !== 'ENOENT') throw scanErr;
    }

    // CloudTrail runs have cloudtrail_ai_summary.json but no scan_result.json.
    // Return a synthesized scan result so the Dashboard and other pages render instead of 404.
    try {
      await fs.access(cloudtrailSummaryPath);
    } catch {
      return res.status(404).json({ error: 'Scan result not found' });
    }

    let scanDate = new Date().toISOString();
    try {
      const stat = await fs.stat(runPath);
      scanDate = (stat.birthtime || stat.mtime).toISOString();
    } catch {
      // use default
    }

    const cloudtrailScanResult = {
      provider: 'cloudtrail',
      account_id: null,
      regions: [],
      checks: [],
      findings: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        skipped: 0,
        errors: 0
      },
      partial_failure: false,
      fatal_error: false,
      risk_score: 0,
      scan_date: scanDate
    };

    res.json(cloudtrailScanResult);
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'Scan result not found' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Get AI summary from a run
runsRouter.get('/:id/ai-summary', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const summaryPath = path.join(runsDir, req.params.id, 'cloudtrail_ai_summary.json');
    
    const content = await fs.readFile(summaryPath, 'utf-8');
    res.json(JSON.parse(content));
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'AI summary not found' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Get extracted indicators (IOCs) from a run's AI summary
runsRouter.get('/:id/indicators', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const summaryPath = path.join(runsDir, req.params.id, 'cloudtrail_ai_summary.json');
    
    const content = await fs.readFile(summaryPath, 'utf-8');
    const summary = JSON.parse(content);
    
    // Extract indicators from the summary
    const indicators = summary.extracted_indicators || null;
    
    if (!indicators) {
      // Return empty indicators structure if not present
      return res.json({
        runId: req.params.id,
        hasIndicators: false,
        indicators: {
          ips: [],
          ips_count: 0,
          access_key_ids: [],
          access_key_ids_count: 0,
          identities: [],
          identities_count: 0,
          user_agents: [],
          user_agents_count: 0,
          domains: [],
          domains_count: 0,
          event_sources: [],
          regions: []
        }
      });
    }
    
    res.json({
      runId: req.params.id,
      hasIndicators: true,
      indicators
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'No AI summary found for this run' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Get exports from a run
runsRouter.get('/:id/exports', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const exportsDir = path.join(runsDir, req.params.id, 'exports');
    
    try {
      await fs.access(exportsDir);
    } catch {
      return res.json({ exports: [] });
    }
    
    const entries = await fs.readdir(exportsDir);
    const exports = [];
    
    for (const entry of entries) {
      const filePath = path.join(exportsDir, entry);
      const stat = await fs.stat(filePath);
      
      if (stat.isFile()) {
        exports.push({
          name: entry,
          path: filePath,
          size: stat.size,
          format: getExportFormat(entry)
        });
      }
    }
    
    res.json({ exports });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getExportFormat(filename) {
  if (filename.includes('.sigma.')) return 'sigma';
  if (filename.includes('.kql.')) return 'kql';
  if (filename.includes('.splunk.')) return 'splunk';
  if (filename.includes('.cloudwatch.')) return 'cloudwatch';
  if (filename.endsWith('.json')) return 'json';
  return 'unknown';
}

// Download an export file
runsRouter.get('/:id/exports/:filename', async (req, res) => {
  try {
    const runsDir = await getRunsDir();
    const filePath = path.join(runsDir, req.params.id, 'exports', req.params.filename);
    
    // Security check
    if (!filePath.startsWith(runsDir)) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    
    const content = await fs.readFile(filePath, 'utf-8');
    
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.filename}"`);
    res.send(content);
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.status(404).json({ error: 'File not found' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// ============================================================
// Scan Execution
// ============================================================

// Get current AWS profile from UI config
const getAWSProfile = async () => {
  try {
    const uiConfigPath = path.join(os.homedir(), '.cti-checkup', 'ui_config.json');
    const content = await fs.readFile(uiConfigPath, 'utf-8');
    const config = JSON.parse(content);
    return config.awsProfile || null;
  } catch {
    return null;
  }
};

// Get config file path from UI config
const getConfigPath = async () => {
  try {
    const uiConfigPath = path.join(os.homedir(), '.cti-checkup', 'ui_config.json');
    const content = await fs.readFile(uiConfigPath, 'utf-8');
    const config = JSON.parse(content);
    const raw = config.configPath || null;
    return raw ? normalizePathForRuntime(raw) : null;
  } catch {
    return null;
  }
};

// Generate a unique run ID
const generateRunId = () => {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
};

// Start a new scan
runsRouter.post('/start', async (req, res) => {
  try {
    const { provider = 'aws', regions, profile, configPath, checks } = req.body;
    
    if (provider !== 'aws') {
      return res.status(400).json({ error: 'Only AWS provider is currently supported' });
    }
    
    const runsDir = await getRunsDir();
    const runId = generateRunId();
    const outputDir = path.join(runsDir, runId);
    const outputFile = path.join(outputDir, 'scan_result.json');
    
    // Ensure runs directory exists
    await fs.mkdir(outputDir, { recursive: true });
    
    // Build CLI arguments
    // --output json: output format (human/json)
    // --out <file>: write output to file
    const args = ['cloud', 'aws', 'scan', '--output', 'json', '--out', outputFile];
    
    // Add profile (from request or UI config)
    const awsProfile = profile || await getAWSProfile();
    if (awsProfile) {
      args.push('--profile', awsProfile);
    }
    
    // Add config path (from request or UI config, or default)
    const rawConfigPath = configPath || await getConfigPath() || defaultConfigPath;
    const yamlConfigPath = normalizePathForRuntime(rawConfigPath);
    args.push('--config', yamlConfigPath);
    
    // Add regions if specified
    if (regions && regions.length > 0) {
      args.push('--regions', regions.join(','));
    }
    
    // Add specific checks if specified
    if (checks && checks.length > 0) {
      args.push('--checks', checks.join(','));
    }
    
    // Get fresh env vars (process.env + current ~/.cti-checkup/.env)
    // This ensures newly added API keys are available without server restart
    const spawnEnv = await getSpawnEnv();
    
    // Spawn the CLI process
    const cliProcess = spawn('cti-checkup', args, {
      shell: true,
      cwd: process.cwd(),
      env: spawnEnv
    });
    
    // Track scan state
    const scanState = {
      id: runId,
      status: 'running',
      startedAt: new Date().toISOString(),
      endedAt: null,
      exitCode: null,
      output: [],
      errors: [],
      args,
      pid: cliProcess.pid
    };
    
    activeScans.set(runId, scanState);
    
    // Capture stdout
    cliProcess.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      scanState.output.push(...lines);
    });
    
    // Capture stderr
    cliProcess.stderr.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      scanState.errors.push(...lines);
    });
    
    // Handle process completion
    cliProcess.on('close', (code) => {
      scanState.status = code === 0 ? 'completed' : 'failed';
      scanState.endedAt = new Date().toISOString();
      scanState.exitCode = code;
      
      // Clean up after configured timeout
      setTimeout(() => {
        activeScans.delete(runId);
      }, DEFAULTS.SCAN_CLEANUP_TIMEOUT_MS);
    });
    
    // Handle process error
    cliProcess.on('error', (err) => {
      scanState.status = 'error';
      scanState.endedAt = new Date().toISOString();
      scanState.errors.push(`Process error: ${err.message}`);
    });
    
    res.json({
      success: true,
      runId,
      outputDir,
      args,
      status: 'running',
      message: 'Scan started successfully'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start CloudTrail analysis
runsRouter.post('/start-cloudtrail', async (req, res) => {
  try {
    const { eventsContent, mode = 'baseline', configPath } = req.body;
    
    if (!eventsContent) {
      return res.status(400).json({ error: 'eventsContent is required (CloudTrail events JSON)' });
    }
    
    const runsDir = await getRunsDir();
    const runId = generateRunId() + '_cloudtrail';
    const outputDir = path.join(runsDir, runId);
    const eventsFile = path.join(outputDir, 'cloudtrail_events.json');
    const summaryFile = path.join(outputDir, 'cloudtrail_ai_summary.json');
    
    // Ensure run directory exists
    await fs.mkdir(outputDir, { recursive: true });
    
    // Write events file
    await fs.writeFile(eventsFile, eventsContent, 'utf-8');
    
    // Set initial run name: CloudTrail_Baseline 2/15/2026 03:58 PM
    const now = new Date();
    const dateLabel = now.toLocaleString('en-US', { month: 'numeric', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
    const prefix = mode === 'llm' ? 'CloudTrail_AiInsights' : 'CloudTrail_Baseline';
    const initialName = `${prefix} ${dateLabel}`;
    const cloudtrailMode = mode === 'llm' ? 'llm' : 'baseline';
    const metaPath = path.join(outputDir, 'run_metadata.json');
    await fs.writeFile(metaPath, JSON.stringify({ name: initialName, cloudtrail_mode: cloudtrailMode }, null, 2), 'utf-8');
    
    // Build CLI arguments
    const args = [
      'ai', 'summarize', 'cloudtrail',
      '--events', eventsFile,
      '--output', 'json',
      '--out', summaryFile,
      '--mode', mode
    ];
    
    // Add config path: for AI mode, prefer ai.local.yaml when no explicit config is set
    let rawYamlPath = configPath || await getConfigPath();
    if (!rawYamlPath) {
      rawYamlPath = (mode === 'llm')
        ? (await fs.access(aiConfigPath).then(() => aiConfigPath).catch(() => defaultConfigPath))
        : defaultConfigPath;
    }
    if (rawYamlPath) {
      const yamlConfigPath = normalizePathForRuntime(rawYamlPath);
      args.push('--config', yamlConfigPath);
    }
    
    // Get fresh env vars (process.env + current ~/.cti-checkup/.env)
    // This ensures newly added API keys are available without server restart
    const spawnEnv = await getSpawnEnv();
    
    // Spawn the CLI process
    const cliProcess = spawn('cti-checkup', args, {
      shell: true,
      cwd: process.cwd(),
      env: spawnEnv
    });
    
    // Track analysis state
    const analysisState = {
      id: runId,
      type: 'cloudtrail',
      status: 'running',
      startedAt: new Date().toISOString(),
      endedAt: null,
      exitCode: null,
      output: [],
      errors: [],
      args,
      pid: cliProcess.pid
    };
    
    activeScans.set(runId, analysisState);
    
    // Capture stdout
    cliProcess.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      analysisState.output.push(...lines);
    });
    
    // Capture stderr
    cliProcess.stderr.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      analysisState.errors.push(...lines);
    });
    
    // Handle process completion
    cliProcess.on('close', (code) => {
      analysisState.status = code === 0 ? 'completed' : 'failed';
      analysisState.endedAt = new Date().toISOString();
      analysisState.exitCode = code;
      
      // Clean up after configured timeout
      setTimeout(() => {
        activeScans.delete(runId);
      }, DEFAULTS.SCAN_CLEANUP_TIMEOUT_MS);
    });
    
    // Handle process error
    cliProcess.on('error', (err) => {
      analysisState.status = 'error';
      analysisState.endedAt = new Date().toISOString();
      analysisState.errors.push(`Process error: ${err.message}`);
    });
    
    res.json({
      success: true,
      runId,
      outputDir,
      args,
      status: 'running',
      message: 'CloudTrail analysis started successfully'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get active scans
runsRouter.get('/active', async (req, res) => {
  const scans = [];
  for (const [id, scan] of activeScans.entries()) {
    scans.push({
      id,
      status: scan.status,
      startedAt: scan.startedAt,
      endedAt: scan.endedAt,
      exitCode: scan.exitCode,
      outputLines: scan.output.length,
      errorLines: scan.errors.length
    });
  }
  res.json({ scans });
});

// Get status of a specific active scan
runsRouter.get('/active/:id', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Active scan not found' });
  }
  
  res.json({
    id: scan.id,
    status: scan.status,
    startedAt: scan.startedAt,
    endedAt: scan.endedAt,
    exitCode: scan.exitCode,
    output: scan.output.slice(-50), // Last 50 lines
    errors: scan.errors.slice(-20),  // Last 20 errors
    args: scan.args,
    pid: scan.pid
  });
});

// Cancel an active scan
runsRouter.post('/active/:id/cancel', async (req, res) => {
  const scan = activeScans.get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Active scan not found' });
  }
  
  if (scan.status !== 'running') {
    return res.status(400).json({ error: 'Scan is not running' });
  }
  
  try {
    process.kill(scan.pid);
    scan.status = 'cancelled';
    scan.endedAt = new Date().toISOString();
    res.json({ success: true, message: 'Scan cancelled' });
  } catch (err) {
    res.status(500).json({ error: `Failed to cancel scan: ${err.message}` });
  }
});
