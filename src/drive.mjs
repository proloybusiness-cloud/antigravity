import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * StorageDrive abstracts the Google Drive storage layer ("Hard Drive").
 *
 * - In "live" mode (or "auto" when Google credentials are present), it talks
 *   directly to Google Drive REST API v3 using native fetch + RS256 Service
 *   Account JWT or OAuth2 Refresh Token (zero external SDK dependencies).
 * - In "local" mode (or "auto" without credentials), it uses a structured local
 *   Drive mirror under `data/drive/` with identical semantics so the full
 *   workflow engine can be tested end-to-end immediately.
 */
export class StorageDrive {
  constructor(config) {
    this.config = config;
    this.gdrive = config.gdrive;
    this.localDir = config.localDriveDir;
    this._accessToken = null;
    this._tokenExpiresAt = 0;

    this.serviceAccount = this._loadServiceAccount();
    this.hasOAuth = Boolean(
      this.gdrive.clientId && this.gdrive.clientSecret && this.gdrive.refreshToken
    );
    this.hasCredentials = Boolean(this.serviceAccount || this.hasOAuth);

    if (this.gdrive.mode === 'live' && !this.hasCredentials) {
      throw new Error(
        'GDRIVE_MODE=live requires either GOOGLE_SERVICE_ACCOUNT_JSON/PATH or GOOGLE_CLIENT_ID+SECRET+REFRESH_TOKEN'
      );
    }

    this.mode =
      this.gdrive.mode === 'local'
        ? 'local-sandbox'
        : this.hasCredentials
          ? 'google-drive-live'
          : 'local-sandbox';

    if (this.mode === 'local-sandbox') {
      fs.mkdirSync(this.localDir, { recursive: true });
      this._indexPath = path.join(this.localDir, '.drive-index.json');
      if (!fs.existsSync(this._indexPath)) {
        fs.writeFileSync(this._indexPath, JSON.stringify({ files: {} }, null, 2));
      }
    }
  }

  getInfo() {
    return {
      mode: this.mode,
      live: this.mode === 'google-drive-live',
      authType: this.serviceAccount
        ? 'service-account'
        : this.hasOAuth
          ? 'oauth2-refresh-token'
          : 'none',
      folderId: this.gdrive.folderId || null,
      localDir: this.mode === 'local-sandbox' ? this.localDir : null,
    };
  }

  _loadServiceAccount() {
    try {
      if (this.gdrive.serviceAccountJson) {
        return JSON.parse(this.gdrive.serviceAccountJson);
      }
      if (this.gdrive.serviceAccountPath && fs.existsSync(this.gdrive.serviceAccountPath)) {
        return JSON.parse(fs.readFileSync(this.gdrive.serviceAccountPath, 'utf8'));
      }
    } catch {
      return null;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Public Unified Storage Interface
  // ---------------------------------------------------------------------------

  async list({ prefix = '', limit = 100 } = {}) {
    if (this.mode === 'google-drive-live') {
      return this._liveList({ prefix, limit });
    }
    return this._localList({ prefix, limit });
  }

  async upload({ name, content, mimeType = 'text/plain', overwrite = true, metadata = {} }) {
    if (!name || typeof name !== 'string') {
      throw new Error('Drive upload requires a file name');
    }
    const cleanName = sanitizeFileName(name);
    const bodyString =
      typeof content === 'string' ? content : JSON.stringify(content ?? '', null, 2);

    if (this.mode === 'google-drive-live') {
      return this._liveUpload({ name: cleanName, content: bodyString, mimeType, overwrite });
    }
    return this._localUpload({
      name: cleanName,
      content: bodyString,
      mimeType,
      overwrite,
      metadata,
    });
  }

  async download({ fileId = '', name = '' }) {
    if (this.mode === 'google-drive-live') {
      return this._liveDownload({ fileId, name });
    }
    return this._localDownload({ fileId, name });
  }

  async delete({ fileId = '', name = '' }) {
    if (this.mode === 'google-drive-live') {
      return this._liveDelete({ fileId, name });
    }
    return this._localDelete({ fileId, name });
  }

  async getStats() {
    const files = await this.list({ limit: 500 });
    const totalBytes = files.reduce((acc, f) => acc + (Number(f.size) || 0), 0);
    return {
      ...this.getInfo(),
      fileCount: files.length,
      totalBytes,
    };
  }

  // ---------------------------------------------------------------------------
  // Local Sandbox Mirror Implementation
  // ---------------------------------------------------------------------------

  _readLocalIndex() {
    try {
      return JSON.parse(fs.readFileSync(this._indexPath, 'utf8'));
    } catch {
      return { files: {} };
    }
  }

  _writeLocalIndex(index) {
    fs.writeFileSync(this._indexPath, JSON.stringify(index, null, 2));
  }

  _localList({ prefix = '', limit = 100 }) {
    const index = this._readLocalIndex();
    let files = Object.values(index.files);
    if (prefix) {
      files = files.filter((f) => f.name.startsWith(prefix));
    }
    files.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return files.slice(0, Number(limit) || 100);
  }

  _localUpload({ name, content, mimeType, overwrite, metadata }) {
    const index = this._readLocalIndex();
    const existing = Object.values(index.files).find((f) => f.name === name);
    const now = new Date().toISOString();

    let id = existing && overwrite ? existing.id : `drv_${crypto.randomBytes(6).toString('hex')}`;
    const storedName = existing && !overwrite ? `${Date.now()}_${name}` : name;
    const targetPath = safeJoin(this.localDir, storedName);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, content, 'utf8');

    const record = {
      id,
      name: storedName,
      mimeType,
      size: Buffer.byteLength(content, 'utf8'),
      createdAt: existing && overwrite ? existing.createdAt : now,
      updatedAt: now,
      storage: 'local-sandbox',
      metadata,
    };
    index.files[id] = record;
    this._writeLocalIndex(index);
    return record;
  }

  _localDownload({ fileId, name }) {
    const index = this._readLocalIndex();
    const record = fileId
      ? index.files[fileId]
      : Object.values(index.files).find((f) => f.name === sanitizeFileName(name));
    if (!record) {
      throw new Error(`Drive file not found: ${fileId || name}`);
    }
    const targetPath = safeJoin(this.localDir, record.name);
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Drive file missing on disk: ${record.name}`);
    }
    const content = fs.readFileSync(targetPath, 'utf8');
    return { ...record, content };
  }

  _localDelete({ fileId, name }) {
    const index = this._readLocalIndex();
    const record = fileId
      ? index.files[fileId]
      : Object.values(index.files).find((f) => f.name === sanitizeFileName(name));
    if (!record) return { deleted: false };

    const targetPath = safeJoin(this.localDir, record.name);
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath);
    }
    delete index.files[record.id];
    this._writeLocalIndex(index);
    return { deleted: true, id: record.id, name: record.name };
  }

  // ---------------------------------------------------------------------------
  // Live Google Drive API v3 Implementation (Zero External Dependencies)
  // ---------------------------------------------------------------------------

  async _getAccessToken() {
    if (this._accessToken && Date.now() < this._tokenExpiresAt - 60_000) {
      return this._accessToken;
    }

    if (this.serviceAccount) {
      const now = Math.floor(Date.now() / 1000);
      const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const claim = base64Url(
        JSON.stringify({
          iss: this.serviceAccount.client_email,
          scope: 'https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive',
          aud: 'https://oauth2.googleapis.com/token',
          exp: now + 3600,
          iat: now,
        })
      );
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(`${header}.${claim}`);
      const signature = signer
        .sign(this.serviceAccount.private_key)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

      const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: `${header}.${claim}.${signature}`,
        }),
      });
      if (!res.ok) {
        throw new Error(`Google Service Account auth failed (${res.status}): ${await res.text()}`);
      }
      const data = await res.json();
      this._accessToken = data.access_token;
      this._tokenExpiresAt = Date.now() + (data.expires_in || 3600) * 1000;
      return this._accessToken;
    }

    // OAuth2 Refresh Token flow
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.gdrive.clientId,
        client_secret: this.gdrive.clientSecret,
        refresh_token: this.gdrive.refreshToken,
        grant_type: 'refresh_token',
      }),
    });
    if (!res.ok) {
      throw new Error(`Google OAuth2 refresh failed (${res.status}): ${await res.text()}`);
    }
    const data = await res.json();
    this._accessToken = data.access_token;
    this._tokenExpiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    return this._accessToken;
  }

  async _liveList({ prefix = '', limit = 100 }) {
    const token = await this._getAccessToken();
    const clauses = ['trashed = false'];
    if (this.gdrive.folderId) {
      clauses.push(`'${escapeDriveQuery(this.gdrive.folderId)}' in parents`);
    }
    if (prefix) {
      clauses.push(`name contains '${escapeDriveQuery(prefix)}'`);
    }
    const url = new URL('https://www.googleapis.com/drive/v3/files');
    url.searchParams.set('q', clauses.join(' and '));
    url.searchParams.set('pageSize', String(Math.min(Number(limit) || 100, 500)));
    url.searchParams.set('fields', 'files(id,name,mimeType,size,createdTime,modifiedTime,webViewLink)');
    url.searchParams.set('orderBy', 'modifiedTime desc');

    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`Google Drive list failed (${res.status}): ${await res.text()}`);
    }
    const data = await res.json();
    return (data.files || []).map((f) => ({
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      size: Number(f.size || 0),
      createdAt: f.createdTime,
      updatedAt: f.modifiedTime,
      webViewLink: f.webViewLink || null,
      storage: 'google-drive-live',
    }));
  }

  async _liveUpload({ name, content, mimeType, overwrite }) {
    const token = await this._getAccessToken();
    let existingId = null;

    if (overwrite) {
      const files = await this._liveList({ prefix: name, limit: 20 });
      const match = files.find((f) => f.name === name);
      if (match) existingId = match.id;
    }

    const boundary = `antigravity_${crypto.randomBytes(8).toString('hex')}`;
    const meta = { name, mimeType };
    if (!existingId && this.gdrive.folderId) {
      meta.parents = [this.gdrive.folderId];
    }

    const body = [
      `--${boundary}`,
      'Content-Type: application/json; charset=UTF-8',
      '',
      JSON.stringify(meta),
      `--${boundary}`,
      `Content-Type: ${mimeType}`,
      '',
      content,
      `--${boundary}--`,
    ].join('\r\n');

    const endpoint = existingId
      ? `https://www.googleapis.com/upload/drive/v3/files/${encodeURIComponent(existingId)}?uploadType=multipart&fields=id,name,mimeType,size,createdTime,modifiedTime,webViewLink`
      : 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,mimeType,size,createdTime,modifiedTime,webViewLink';

    const res = await fetch(endpoint, {
      method: existingId ? 'PATCH' : 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': `multipart/related; boundary=${boundary}`,
      },
      body,
    });

    if (!res.ok) {
      throw new Error(`Google Drive upload failed (${res.status}): ${await res.text()}`);
    }
    const f = await res.json();
    return {
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      size: Number(f.size || Buffer.byteLength(content, 'utf8')),
      createdAt: f.createdTime,
      updatedAt: f.modifiedTime,
      webViewLink: f.webViewLink || null,
      storage: 'google-drive-live',
    };
  }

  async _liveDownload({ fileId, name }) {
    const token = await this._getAccessToken();
    let targetId = fileId;
    let fileMeta = null;

    if (!targetId && name) {
      const files = await this._liveList({ prefix: name, limit: 20 });
      fileMeta = files.find((f) => f.name === name);
      if (!fileMeta) throw new Error(`Google Drive file not found: ${name}`);
      targetId = fileMeta.id;
    }

    if (!fileMeta) {
      const metaRes = await fetch(
        `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(targetId)}?fields=id,name,mimeType,size,createdTime,modifiedTime,webViewLink`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!metaRes.ok) {
        throw new Error(`Google Drive metadata failed (${metaRes.status}): ${await metaRes.text()}`);
      }
      const f = await metaRes.json();
      fileMeta = {
        id: f.id,
        name: f.name,
        mimeType: f.mimeType,
        size: Number(f.size || 0),
        createdAt: f.createdTime,
        updatedAt: f.modifiedTime,
        webViewLink: f.webViewLink || null,
        storage: 'google-drive-live',
      };
    }

    const res = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(targetId)}?alt=media`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok) {
      throw new Error(`Google Drive download failed (${res.status}): ${await res.text()}`);
    }
    return { ...fileMeta, content: await res.text() };
  }

  async _liveDelete({ fileId, name }) {
    const token = await this._getAccessToken();
    let targetId = fileId;
    if (!targetId && name) {
      const files = await this._liveList({ prefix: name, limit: 20 });
      const match = files.find((f) => f.name === name);
      if (!match) return { deleted: false };
      targetId = match.id;
    }
    const res = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(targetId)}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok && res.status !== 404) {
      throw new Error(`Google Drive delete failed (${res.status}): ${await res.text()}`);
    }
    return { deleted: res.ok, id: targetId };
  }
}

function base64Url(str) {
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function escapeDriveQuery(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function sanitizeFileName(name) {
  const normalized = String(name)
    .replace(/\\/g, '/')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/');
  if (!normalized) throw new Error('Invalid file name');
  return normalized;
}

function safeJoin(baseDir, relPath) {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, relPath);
  if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
    throw new Error(`Unsafe file path blocked: ${relPath}`);
  }
  return resolvedTarget;
}
