import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { configRouter } from './routes/config.js';
import { awsRouter } from './routes/aws.js';
import { secretsRouter, computeSecretsStatus, SECRET_KEYS } from './routes/secrets.js';
import { runsRouter } from './routes/runs.js';
import { intelRouter } from './routes/intel.js';

// Get project root (server → frontend → project root)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..', '..');
const ctiCheckupEnvPath = path.join(os.homedir(), '.cti-checkup', '.env');
const projectEnvPath = path.join(projectRoot, '.env');

dotenv.config({ path: ctiCheckupEnvPath });
dotenv.config({ path: projectEnvPath });

console.log('Loaded env from:', ctiCheckupEnvPath, 'and', projectEnvPath);

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    name: 'CTI-Checkup API Server',
    version: '1.0.0',
    endpoints: ['/api/health', '/api/config', '/api/aws', '/api/secrets', '/api/runs', '/api/intel']
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api/config', configRouter);
app.use('/api/aws', awsRouter);
app.use('/api/secrets', secretsRouter);
app.use('/api/runs', runsRouter);
app.use('/api/intel', intelRouter);

app.listen(PORT, async () => {
  console.log(`CTI-Checkup API server running on http://localhost:${PORT}`);
  try {
    const { status } = await computeSecretsStatus();
    console.log('API keys status (same logic as UI):');
    for (const key of SECRET_KEYS) {
      const s = status[key];
      console.log(`  ${key}: ${s?.configured ? 'configured' : 'not set'}${s?.source ? ` (${s.source})` : ''}`);
    }
  } catch (err) {
    console.warn('Could not log API keys status:', err.message);
  }
});
