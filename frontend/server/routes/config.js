import { Router } from 'express';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';
import os from 'os';
import { normalizePathForRuntime } from '../lib/paths.js';

export const configRouter = Router();

// Default paths
const getDefaultConfigPath = () => {
  const cwd = process.cwd();
  // Go up from server to frontend to project root
  const projectRoot = path.resolve(cwd, '..', '..');
  return path.join(projectRoot, 'config', 'local.yaml');
};

const getUIConfigPath = () => {
  return path.join(os.homedir(), '.cti-checkup', 'ui_config.json');
};

// Ensure directory exists
async function ensureDir(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
}

// Get UI config
configRouter.get('/ui', async (req, res) => {
  try {
    const configPath = getUIConfigPath();
    const data = await fs.readFile(configPath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    if (err.code === 'ENOENT') {
      // Return default config if file doesn't exist
      res.json({
        configPath: getDefaultConfigPath(),
        runsDirectory: path.join(os.homedir(), '.cti-checkup', 'runs'),
        timezone: 'UTC',
        awsProfile: null,
        theme: 'dark'
      });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Save UI config
configRouter.post('/ui', async (req, res) => {
  try {
    const configPath = getUIConfigPath();
    await ensureDir(path.dirname(configPath));
    await fs.writeFile(configPath, JSON.stringify(req.body, null, 2));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get main YAML config
configRouter.get('/yaml', async (req, res) => {
  try {
    const rawPath = req.query.path || getDefaultConfigPath();
    const configPath = normalizePathForRuntime(rawPath);
    const data = await fs.readFile(configPath, 'utf-8');
    const parsed = yaml.load(data);
    res.json({ path: configPath, content: parsed, raw: data });
  } catch (err) {
    if (err.code === 'ENOENT') {
      // Return empty config if file doesn't exist
      const rawPath = req.query.path || getDefaultConfigPath();
      res.json({ path: normalizePathForRuntime(rawPath), content: {}, raw: '' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// Save main YAML config
configRouter.post('/yaml', async (req, res) => {
  try {
    const { path: rawConfigPath, content } = req.body;
    const configPath = normalizePathForRuntime(rawConfigPath);
    
    // Validate YAML structure
    if (typeof content === 'string') {
      yaml.load(content); // This will throw if invalid YAML
      await ensureDir(path.dirname(configPath));
      await fs.writeFile(configPath, content);
    } else {
      const yamlStr = yaml.dump(content, { indent: 2, lineWidth: -1 });
      await ensureDir(path.dirname(configPath));
      await fs.writeFile(configPath, yamlStr);
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Validate YAML
configRouter.post('/yaml/validate', async (req, res) => {
  try {
    const { content } = req.body;
    yaml.load(content);
    res.json({ valid: true });
  } catch (err) {
    res.json({ valid: false, error: err.message });
  }
});

// List available config files
configRouter.get('/list', async (req, res) => {
  try {
    const cwd = process.cwd();
    const projectRoot = path.resolve(cwd, '..', '..');
    const configDir = path.join(projectRoot, 'config');
    
    const files = await fs.readdir(configDir);
    const yamlFiles = files
      .filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))
      .map(f => ({
        name: f,
        path: path.join(configDir, f)
      }));
    
    res.json({ configDir, files: yamlFiles });
  } catch (err) {
    res.json({ configDir: '', files: [] });
  }
});

// Get example config structure
configRouter.get('/schema', async (req, res) => {
  res.json({
    aws: {
      regions: ['us-east-1'],
      checks: {
        s3: { enabled: true },
        iam: { enabled: true },
        ec2: { enabled: true }
      }
    },
    ai: {
      enabled: false,
      provider: 'openai',
      model: 'gpt-4',
      temperature: 0.2,
      max_tokens: 4096,
      timeout: 60,
      max_input_events: 1000
    },
    export: {
      enabled: true,
      formats: ['sigma', 'kql', 'cloudwatch', 'splunk'],
      templates_dir: './templates'
    },
    risk_scoring: {
      weights: { critical: 25, high: 15, medium: 5, low: 1 },
      cap: 100
    }
  });
});
