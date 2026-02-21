/**
 * Path normalization for cross-platform compatibility.
 * Accepts Windows paths (C:\..., C:/...) and WSL paths (/mnt/c/...).
 * Converts to the format expected by the current runtime environment.
 */
import path from 'path';

/**
 * Normalize a path so it works in the current runtime environment.
 * - On Windows: converts /mnt/c/... to C:\... if needed; otherwise keeps Windows paths as-is.
 * - On Linux/WSL: converts C:\... or C:/... to /mnt/c/... ; keeps Unix paths as-is.
 *
 * @param {string} inputPath - Path from user (Windows or WSL format)
 * @returns {string} Path suitable for the current OS
 */
export function normalizePathForRuntime(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') return inputPath;
  const trimmed = inputPath.trim();
  if (!trimmed) return inputPath;

  if (process.platform === 'win32') {
    // On Windows: convert /mnt/c/... to C:\... when user copies from WSL
    const wslMatch = trimmed.match(/^\/mnt\/([a-zA-Z])\/(.*)$/);
    if (wslMatch) {
      const drive = wslMatch[1].toUpperCase();
      const rest = wslMatch[2].replace(/\//g, path.sep);
      return rest ? `${drive}:${path.sep}${rest}` : `${drive}:${path.sep}`;
    }
    return trimmed;
  }

  // On Linux/WSL: convert C:\... or C:/... to /mnt/c/...
  const winMatch = trimmed.match(/^([A-Za-z]):[\\/]?(.*)$/);
  if (winMatch) {
    const drive = winMatch[1].toLowerCase();
    const rest = (winMatch[2] || '').replace(/\\/g, '/');
    return rest ? `/mnt/${drive}/${rest}` : `/mnt/${drive}/`;
  }

  return trimmed;
}
