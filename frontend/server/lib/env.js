/**
 * Shared environment variable utilities for .env files.
 * Primary storage: project root .env. Fallback: ~/.cti-checkup/.env
 */
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { normalizePathForRuntime } from './paths.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Project root: frontend/server/lib -> .. -> server, .. -> frontend, .. -> project root
const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');

/**
 * Get the path to the project root .env file (primary storage for API keys from UI).
 * @returns {string} Path to project/.env
 */
export function getProjectEnvPath() {
  return path.join(PROJECT_ROOT, '.env');
}

/**
 * Get the path to the user's .env file (fallback, e.g. ~/.cti-checkup/.env).
 * @returns {string} Path to ~/.cti-checkup/.env
 */
export function getEnvPath() {
  return path.join(os.homedir(), '.cti-checkup', '.env');
}

/**
 * Ensure a directory exists, creating it if necessary.
 * @param {string} dirPath - Directory path to ensure exists
 */
export async function ensureDir(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
}

/**
 * Parse a .env file and return an object of key-value pairs.
 * Handles comments, empty lines, and quoted values.
 * @param {string} filePath - Path to the .env file
 * @returns {Promise<Object<string, string>>} Parsed environment variables
 */
export async function parseEnvFile(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const vars = {};
    
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1).trim();
        // Remove quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) || 
            (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        vars[key] = value;
      }
    }
    
    return vars;
  } catch (err) {
    // File doesn't exist or can't be read - return empty object
    return {};
  }
}

/**
 * Write environment variables to a .env file.
 * @param {string} filePath - Path to the .env file
 * @param {Object<string, string>} vars - Key-value pairs to write
 */
export async function writeEnvFile(filePath, vars) {
  const lines = ['# CTI-Checkup secrets - DO NOT COMMIT THIS FILE'];
  
  for (const [key, value] of Object.entries(vars)) {
    if (value !== undefined && value !== null && value !== '') {
      // Quote values that contain spaces or special chars
      const needsQuotes = /[\s#=]/.test(value);
      lines.push(`${key}=${needsQuotes ? `"${value}"` : value}`);
    }
  }
  
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, lines.join('\n') + '\n');
}

/**
 * Set or update a single key in an existing .env file (preserves all other lines and order).
 * Only the line whose key exactly matches is updated; all other lines are left unchanged.
 * @param {string} filePath - Path to the .env file
 * @param {string} key - Environment variable name
 * @param {string} value - New value (use '' to unset/remove the value line)
 */
export async function setKeyInEnvFile(filePath, key, value) {
  let content = '';
  try {
    content = await fs.readFile(filePath, 'utf-8');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const lineKeyRegex = new RegExp(`^([#\\s]*)(${escapedKey})\\s*=(.*)$`);
  const needsQuotes = value && /[\s#=]/.test(value);
  const newLine = value !== undefined && value !== null && value !== ''
    ? `${key}=${needsQuotes ? `"${value}"` : value}`
    : `${key}=`;

  const lines = content.length ? content.split(/\r?\n/) : [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    if (lineKeyRegex.test(lines[i])) {
      lines[i] = newLine;
      found = true;
      break;
    }
  }
  if (!found) {
    lines.push(newLine);
  }

  const newContent = lines.join('\n') + '\n';
  await fs.writeFile(filePath, newContent);
}

/** Env vars that may contain file paths; normalize for the current OS when spawning CLI. */
const PATH_ENV_VARS = ['AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'CTICHECKUP_CONFIG'];

/**
 * Get merged environment variables for CLI spawning.
 * Priority: process.env < user .env < project .env (project is primary for UI-saved keys).
 * Path env vars are normalized for the current runtime (Windows vs WSL/Linux).
 * @returns {Promise<Object<string, string>>} Merged environment variables
 */
export async function getSpawnEnv() {
  const projectVars = await parseEnvFile(getProjectEnvPath());
  const userVars = await parseEnvFile(getEnvPath());
  const merged = { ...process.env, ...userVars, ...projectVars };
  for (const key of PATH_ENV_VARS) {
    if (merged[key]) {
      merged[key] = normalizePathForRuntime(merged[key]);
    }
  }
  return merged;
}
