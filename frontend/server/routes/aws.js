import { Router } from 'express';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import ini from 'ini';
import { normalizePathForRuntime } from '../lib/paths.js';

export const awsRouter = Router();

// ~/.aws is the standard location on all platforms. Resolve home directory:
// - macOS/Linux: uses HOME environment variable
// - Windows: uses USERPROFILE environment variable
// - Fallback: os.homedir()
// Override via AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE env vars if needed.
function getHomeDir() {
  return process.env.HOME || process.env.USERPROFILE || os.homedir();
}
function getAwsDir() {
  return path.join(getHomeDir(), '.aws');
}
function getAwsConfigPath() {
  const raw = process.env.AWS_CONFIG_FILE || path.join(getAwsDir(), 'config');
  return normalizePathForRuntime(raw);
}
function getAwsCredentialsPath() {
  const raw = process.env.AWS_SHARED_CREDENTIALS_FILE || path.join(getAwsDir(), 'credentials');
  return normalizePathForRuntime(raw);
}

// Parse AWS config file to extract profile names
async function parseAwsConfig(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = ini.parse(content);
    
    const profiles = [];
    for (const key of Object.keys(parsed)) {
      // AWS config uses "profile <name>" format, except for default
      if (key === 'default') {
        profiles.push({ name: 'default', source: 'config' });
      } else if (key.startsWith('profile ')) {
        profiles.push({ name: key.replace('profile ', ''), source: 'config' });
      }
    }
    return profiles;
  } catch (err) {
    return [];
  }
}

// Parse AWS credentials file to extract profile names
async function parseAwsCredentials(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = ini.parse(content);
    
    return Object.keys(parsed).map(name => ({ name, source: 'credentials' }));
  } catch (err) {
    return [];
  }
}

// Get all AWS profiles
awsRouter.get('/profiles', async (req, res) => {
  try {
    const configProfiles = await parseAwsConfig(getAwsConfigPath());
    const credentialProfiles = await parseAwsCredentials(getAwsCredentialsPath());
    
    // Merge profiles, preferring config info
    const profileMap = new Map();
    
    for (const p of credentialProfiles) {
      profileMap.set(p.name, { ...p, hasCredentials: true });
    }
    
    for (const p of configProfiles) {
      const existing = profileMap.get(p.name);
      if (existing) {
        profileMap.set(p.name, { ...existing, ...p, hasConfig: true });
      } else {
        profileMap.set(p.name, { ...p, hasConfig: true, hasCredentials: false });
      }
    }
    
    const profiles = Array.from(profileMap.values()).sort((a, b) => {
      if (a.name === 'default') return -1;
      if (b.name === 'default') return 1;
      return a.name.localeCompare(b.name);
    });
    
    res.json({
      profiles,
      configPath: getAwsConfigPath(),
      credentialsPath: getAwsCredentialsPath()
    });
  } catch (err) {
    res.status(500).json({ error: err.message, profiles: [] });
  }
});

// Check if AWS CLI is configured
awsRouter.get('/status', async (req, res) => {
  try {
    const configExists = await fs.access(getAwsConfigPath()).then(() => true).catch(() => false);
    const credentialsExists = await fs.access(getAwsCredentialsPath()).then(() => true).catch(() => false);
    
    res.json({
      configured: configExists || credentialsExists,
      configExists,
      credentialsExists,
      configPath: getAwsConfigPath(),
      credentialsPath: getAwsCredentialsPath()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get common AWS regions
awsRouter.get('/regions', (req, res) => {
  res.json({
    regions: [
      { code: 'us-east-1', name: 'US East (N. Virginia)' },
      { code: 'us-east-2', name: 'US East (Ohio)' },
      { code: 'us-west-1', name: 'US West (N. California)' },
      { code: 'us-west-2', name: 'US West (Oregon)' },
      { code: 'eu-west-1', name: 'Europe (Ireland)' },
      { code: 'eu-west-2', name: 'Europe (London)' },
      { code: 'eu-west-3', name: 'Europe (Paris)' },
      { code: 'eu-central-1', name: 'Europe (Frankfurt)' },
      { code: 'eu-north-1', name: 'Europe (Stockholm)' },
      { code: 'ap-northeast-1', name: 'Asia Pacific (Tokyo)' },
      { code: 'ap-northeast-2', name: 'Asia Pacific (Seoul)' },
      { code: 'ap-southeast-1', name: 'Asia Pacific (Singapore)' },
      { code: 'ap-southeast-2', name: 'Asia Pacific (Sydney)' },
      { code: 'ap-south-1', name: 'Asia Pacific (Mumbai)' },
      { code: 'sa-east-1', name: 'South America (São Paulo)' },
      { code: 'ca-central-1', name: 'Canada (Central)' }
    ]
  });
});
