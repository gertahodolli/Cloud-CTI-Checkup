import { Router } from 'express';
import { getEnvPath, getProjectEnvPath, parseEnvFile, setKeyInEnvFile } from '../lib/env.js';

export const secretsRouter = Router();

// Known secret keys (names must match what the CLI reads via os.environ)
const SECRET_KEYS = [
  'CTICHECKUP_AI_OPENAI_API_KEY',       // OpenAI API key for AI summarization
  'CTICHECKUP_ABUSEIPDB_API_KEY',       // Required for intel ip
  'CTICHECKUP_IPINFO_TOKEN',            // Required for intel domain + cloud attribution
  'CTICHECKUP_IPINFO_REFERRER',         // When IPinfo "Limit Referring Domains" is enabled
  'CTICHECKUP_VIRUSTOTAL_API_KEY',      // Optional for VirusTotal lookups
];

// Helper to mask a secret value (show last 4 chars)
function maskValue(value) {
  if (!value) return null;
  return '••••••••' + (value.slice(-4) || '');
}

// Same logic used by GET /status and by startup log (single source of truth)
async function computeSecretsStatus() {
  const userEnvPath = getEnvPath();
  const projectEnvPath = getProjectEnvPath();
  const projectVars = await parseEnvFile(projectEnvPath);
  const userVars = await parseEnvFile(userEnvPath);
  const status = {};
  for (const key of SECRET_KEYS) {
    const hasProject = Object.prototype.hasOwnProperty.call(projectVars, key);
    const hasUser = Object.prototype.hasOwnProperty.call(userVars, key);
    const projectValue = projectVars[key];
    const userValue = userVars[key];
    const processValue = process.env[key];
    const effectiveValue = hasProject ? projectValue : (hasUser ? userValue : processValue);
    const effectiveSource = hasProject ? 'project' : (hasUser ? 'user' : (processValue ? 'env' : null));
    status[key] = {
      configured: !!effectiveValue,
      masked: maskValue(effectiveValue),
      source: effectiveSource
    };
  }
  return { status, projectEnvPath, userEnvPath };
}

// Get secrets status (not the actual values!)
secretsRouter.get('/status', async (req, res) => {
  try {
    const { status, projectEnvPath, userEnvPath } = await computeSecretsStatus();
    res.json({
      envPath: projectEnvPath,
      projectEnvPath,
      userEnvPath,
      secrets: status
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export { computeSecretsStatus, SECRET_KEYS };

// Set a secret – stored in project root .env; returns fresh status so UI can update immediately
secretsRouter.post('/set', async (req, res) => {
  try {
    const { key, value } = req.body;
    
    if (!SECRET_KEYS.includes(key)) {
      return res.status(400).json({ error: `Unknown secret key: ${key}` });
    }
    
    await setKeyInEnvFile(getProjectEnvPath(), key, value || '');
    const { status, projectEnvPath, userEnvPath } = await computeSecretsStatus();
    
    res.json({
      success: true,
      configured: !!value,
      envPath: projectEnvPath,
      projectEnvPath,
      userEnvPath,
      secrets: status
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a secret (clears value in project root .env)
secretsRouter.delete('/:key', async (req, res) => {
  try {
    const key = decodeURIComponent(req.params.key);
    
    if (!SECRET_KEYS.includes(key)) {
      return res.status(400).json({ error: `Unknown secret key: ${key}` });
    }
    
    await setKeyInEnvFile(getProjectEnvPath(), key, '');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get list of supported secret keys
secretsRouter.get('/keys', (req, res) => {
  res.json({
    keys: SECRET_KEYS.map(key => ({
      key,
      label: key.replace('CTICHECKUP_', '').replace(/_/g, ' '),
      provider: key.includes('OPENAI') ? 'openai' : 
                key.includes('ABUSEIPDB') ? 'abuseipdb' :
                key.includes('IPINFO') ? 'ipinfo' :
                key.includes('VIRUSTOTAL') ? 'virustotal' : 'other'
    }))
  });
});
