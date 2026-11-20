import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const ROOT_DIR = path.resolve(__dirname, '..');

/**
 * Loads key=value pairs from a local .env file without overriding existing
 * process.env variables. Keeps the runtime zero-dependency.
 */
export function loadEnvFile(envPath = path.join(ROOT_DIR, '.env')) {
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex <= 0) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    let val = trimmed.slice(eqIndex + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) {
      process.env[key] = val;
    }
  }
}

loadEnvFile();

/**
 * Resolves runtime configuration from environment variables with sensible
 * defaults so Gen-1 starts immediately for testing without extra setup.
 */
export function getConfig(overrides = {}) {
  const dataDir = path.resolve(ROOT_DIR, overrides.dataDir || process.env.DATA_DIR || './data');
  const workflowsDir = path.resolve(
    ROOT_DIR,
    overrides.workflowsDir || process.env.WORKFLOWS_DIR || './workflows'
  );

  return {
    rootDir: ROOT_DIR,
    port: Number(overrides.port ?? process.env.PORT ?? 3777),
    host: overrides.host ?? process.env.HOST ?? '0.0.0.0',
    nodeEnv: overrides.nodeEnv ?? process.env.NODE_ENV ?? 'development',
    dataDir,
    dbPath: overrides.dbPath || path.join(dataDir, 'core-memory.sqlite'),
    localDriveDir: overrides.localDriveDir || path.join(dataDir, 'drive'),
    workflowsDir,
    apiKey: overrides.apiKey ?? process.env.ANTIGRAVITY_API_KEY ?? '',
    webhookSecret: overrides.webhookSecret ?? process.env.ANTIGRAVITY_WEBHOOK_SECRET ?? '',
    schedulerEnabled:
      overrides.schedulerEnabled ?? (process.env.SCHEDULER_ENABLED ?? 'true').toLowerCase() !== 'false',
    gdrive: {
      mode: (overrides.gdriveMode ?? process.env.GDRIVE_MODE ?? 'auto').toLowerCase(),
      folderId: overrides.googleDriveFolderId ?? process.env.GOOGLE_DRIVE_FOLDER_ID ?? '',
      serviceAccountJson: process.env.GOOGLE_SERVICE_ACCOUNT_JSON ?? '',
      serviceAccountPath: process.env.GOOGLE_SERVICE_ACCOUNT_PATH ?? '',
      clientId: process.env.GOOGLE_CLIENT_ID ?? '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
      refreshToken: process.env.GOOGLE_REFRESH_TOKEN ?? '',
    },
    github: {
      token: process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '',
      repository: process.env.GITHUB_REPOSITORY || 'proloybusiness-cloud/antigravity',
    },
    brain: {
      apiUrl: process.env.BRAIN_API_URL || 'https://api.openai.com/v1/chat/completions',
      apiKey: process.env.BRAIN_API_KEY || '',
      model: process.env.BRAIN_MODEL || 'gpt-4o-mini',
    },
    remoteUrl: process.env.ANTIGRAVITY_REMOTE_URL || '',
  };
}
