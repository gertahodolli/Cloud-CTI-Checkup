import { Router } from 'express';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { getSpawnEnv } from '../lib/env.js';

export const intelRouter = Router();

// Get project root for config path
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..', '..', '..');
const defaultConfigPath = path.join(projectRoot, 'config', 'local.yaml');

// Track active intel queries
const activeQueries = new Map();

// Execute a CLI command and return the result
// Re-reads ~/.cti-checkup/.env on each call so newly added API keys are used without server restart
async function runCLI(args) {
  // Get fresh env vars (process.env + current ~/.cti-checkup/.env)
  const spawnEnv = await getSpawnEnv();
  
  return new Promise((resolve, reject) => {
    const output = [];
    const errors = [];
    
    // Add --config if not already present
    const fullArgs = args.includes('--config') ? args : [...args, '--config', defaultConfigPath];
    
    console.log('Running CLI:', 'cti-checkup', fullArgs.join(' '));
    
    const cliProcess = spawn('cti-checkup', fullArgs, {
      shell: true,
      cwd: process.cwd(),
      env: spawnEnv
    });
    
    cliProcess.stdout.on('data', (data) => {
      output.push(data.toString());
    });
    
    cliProcess.stderr.on('data', (data) => {
      errors.push(data.toString());
    });
    
    cliProcess.on('close', (code) => {
      const fullOutput = output.join('');
      const fullErrors = errors.join('');
      
      console.log('CLI stdout:', fullOutput.slice(0, 500));
      console.log('CLI stderr:', fullErrors.slice(0, 500));
      console.log('CLI exit code:', code);
      
      if (code === 0) {
        // Try to parse as JSON
        try {
          const json = JSON.parse(fullOutput);
          resolve({ success: true, data: json, raw: fullOutput });
        } catch {
          resolve({ success: true, data: null, raw: fullOutput });
        }
      } else {
        // Include stderr in error message for debugging
        const errorMsg = fullErrors || fullOutput || `CLI exited with code ${code}`;
        reject(new Error(errorMsg));
      }
    });
    
    cliProcess.on('error', (err) => {
      reject(err);
    });
  });
}

// Validate IP address
function isValidIP(ip) {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6 (simplified check)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:)+:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => parseInt(part, 10) <= 255);
  }
  
  return ipv6Regex.test(ip);
}

// Validate domain name
function isValidDomain(domain) {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

// ============================================================
// IP Lookup
// ============================================================

// Check IP address
intelRouter.post('/ip', async (req, res) => {
  try {
    const { ip, format = 'json' } = req.body;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }
    
    if (!isValidIP(ip)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }
    
    const queryId = `ip_${ip}_${Date.now()}`;
    activeQueries.set(queryId, { type: 'ip', target: ip, startedAt: new Date().toISOString() });
    
    try {
      const args = ['intel', 'ip', ip];
      if (format === 'json') {
        args.push('--output', 'json');
      }
      
      const result = await runCLI(args);
      activeQueries.delete(queryId);
      
      res.json({
        success: true,
        ip,
        result: result.data || result.raw,
        raw: result.raw
      });
    } catch (err) {
      activeQueries.delete(queryId);
      res.status(500).json({ 
        success: false,
        error: err.message,
        hint: 'Make sure cti-checkup is installed and in your PATH'
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Batch IP lookup
intelRouter.post('/ip/batch', async (req, res) => {
  try {
    const { ips, format = 'json' } = req.body;
    
    if (!ips || !Array.isArray(ips) || ips.length === 0) {
      return res.status(400).json({ error: 'Array of IP addresses is required' });
    }
    
    if (ips.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 IPs per batch' });
    }
    
    const invalidIPs = ips.filter(ip => !isValidIP(ip));
    if (invalidIPs.length > 0) {
      return res.status(400).json({ error: `Invalid IP addresses: ${invalidIPs.join(', ')}` });
    }
    
    const results = [];
    for (const ip of ips) {
      try {
        const args = ['intel', 'ip', ip];
        if (format === 'json') {
          args.push('--output', 'json');
        }
        const result = await runCLI(args);
        results.push({ ip, success: true, result: result.data || result.raw });
      } catch (err) {
        results.push({ ip, success: false, error: err.message });
      }
    }
    
    res.json({
      success: true,
      total: ips.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      results
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// Domain Lookup
// ============================================================

// Check domain
intelRouter.post('/domain', async (req, res) => {
  try {
    const { domain, format = 'json' } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }
    
    const queryId = `domain_${domain}_${Date.now()}`;
    activeQueries.set(queryId, { type: 'domain', target: domain, startedAt: new Date().toISOString() });
    
    try {
      const args = ['intel', 'domain', domain];
      if (format === 'json') {
        args.push('--output', 'json');
      }
      
      const result = await runCLI(args);
      activeQueries.delete(queryId);
      
      res.json({
        success: true,
        domain,
        result: result.data || result.raw,
        raw: result.raw
      });
    } catch (err) {
      activeQueries.delete(queryId);
      res.status(500).json({ 
        success: false,
        error: err.message,
        hint: 'Make sure cti-checkup is installed and in your PATH'
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// Hash Lookup (VirusTotal)
// ============================================================

// Validate hash format
function isValidHash(hash) {
  // MD5 (32), SHA1 (40), SHA256 (64)
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  return hashRegex.test(hash);
}

// Check file hash on VirusTotal
intelRouter.post('/hash', async (req, res) => {
  try {
    const { hash, format = 'json' } = req.body;
    
    if (!hash) {
      return res.status(400).json({ error: 'Hash is required' });
    }
    
    if (!isValidHash(hash)) {
      return res.status(400).json({ error: 'Invalid hash format. Expected MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)' });
    }
    
    const queryId = `hash_${hash}_${Date.now()}`;
    activeQueries.set(queryId, { type: 'hash', target: hash, startedAt: new Date().toISOString() });
    
    try {
      const args = ['intel', 'hash', hash];
      if (format === 'json') {
        args.push('--output', 'json');
      }
      
      const result = await runCLI(args);
      activeQueries.delete(queryId);
      
      res.json({
        success: true,
        hash,
        result: result.data || result.raw,
        raw: result.raw
      });
    } catch (err) {
      activeQueries.delete(queryId);
      res.status(500).json({ 
        success: false,
        error: err.message,
        hint: 'Make sure cti-checkup is installed and CTICHECKUP_VIRUSTOTAL_API_KEY is set'
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// Active Queries
// ============================================================

intelRouter.get('/active', async (req, res) => {
  const queries = [];
  for (const [id, query] of activeQueries.entries()) {
    queries.push({ id, ...query });
  }
  res.json({ queries });
});
