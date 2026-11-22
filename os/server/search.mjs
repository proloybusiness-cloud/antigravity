/**
 * OmniOS Spotlight Universal Search Engine (`F-064`)
 * - Indexes installed 4-platform + Universal apps (incl. macOS Spotlight metadata),
 *   App Hub catalog entries, all 7 built-in system apps, VFS files (bounded scan +
 *   Spotlight xattrs), active processes, system settings & Apple Defaults domains,
 *   and quick OS actions.
 * - Pure Node.js 24 ESM with zero static import of `os/os.mjs`.
 */

const UTF8_DECODER = new TextDecoder('utf-8');
const MAX_QUERY_LENGTH = 256;
const VFS_SCAN_ROOTS = Object.freeze(['/home/user', '/apps', '/packages']);

const TYPE_PRIORITY = Object.freeze({
  app: 5,
  action: 4,
  file: 3,
  setting: 2,
  process: 1,
});

const TYPE_ALIAS_MAP = Object.freeze({
  app: 'app',
  apps: 'app',
  file: 'file',
  files: 'file',
  process: 'process',
  processes: 'process',
  setting: 'setting',
  settings: 'setting',
  action: 'action',
  actions: 'action',
});

const SYSTEM_SETTINGS_CATALOG = Object.freeze({
  'system.theme': Object.freeze({
    title: 'Appearance & Theme',
    description: 'Switch between Dark, Light, and Auto system themes',
    keywords: ['theme', 'dark', 'light', 'auto', 'appearance', 'color', 'ui'],
  }),
  'system.shellMode': Object.freeze({
    title: 'Adaptive Shell Mode',
    description: 'Switch shell UX between Unified Hybrid, Windows, macOS, iOS, and Android',
    keywords: ['shell', 'mode', 'desktop', 'hybrid', 'unified', 'windows', 'macos', 'ios', 'android', 'layout'],
  }),
  'system.volume': Object.freeze({
    title: 'System Volume',
    description: 'Adjust master audio output volume level',
    keywords: ['volume', 'audio', 'sound', 'speaker', 'mute'],
  }),
  'system.brightness': Object.freeze({
    title: 'Display Brightness',
    description: 'Adjust display brightness level',
    keywords: ['brightness', 'display', 'screen', 'backlight', 'dim'],
  }),
  'system.wifi': Object.freeze({
    title: 'Wi-Fi Networking',
    description: 'Toggle wireless Wi-Fi network connectivity',
    keywords: ['wifi', 'wi-fi', 'network', 'wireless', 'internet'],
  }),
  'system.bluetooth': Object.freeze({
    title: 'Bluetooth',
    description: 'Toggle Bluetooth device connectivity',
    keywords: ['bluetooth', 'bt', 'wireless', 'devices', 'audio'],
  }),
  'system.dnd': Object.freeze({
    title: 'Do Not Disturb',
    description: 'Silence incoming notification alerts and focus mode',
    keywords: ['dnd', 'do not disturb', 'focus', 'silent', 'quiet', 'notifications'],
  }),
  'system.locale': Object.freeze({
    title: 'Language & Locale',
    description: 'Configure system language and regional format',
    keywords: ['locale', 'language', 'region', 'international', 'en-us'],
  }),
});

const QUICK_ACTIONS = Object.freeze([
  Object.freeze({
    id: 'action:switch-shell-mode:unified',
    title: 'Switch to Unified Hybrid Shell',
    subtitle: 'Adaptive OS Shell Mode (Unified)',
    action: 'switch-shell-mode:unified',
    keywords: ['shell', 'mode', 'unified', 'hybrid', 'switch', 'layout'],
  }),
  Object.freeze({
    id: 'action:switch-shell-mode:windows',
    title: 'Switch to Windows Shell Mode',
    subtitle: 'Taskbar, Start Menu & Snap Layouts',
    action: 'switch-shell-mode:windows',
    keywords: ['shell', 'mode', 'windows', 'taskbar', 'start', 'switch'],
  }),
  Object.freeze({
    id: 'action:switch-shell-mode:macos',
    title: 'Switch to macOS Shell Mode',
    subtitle: 'Global Menu Bar, Dock & Spotlight',
    action: 'switch-shell-mode:macos',
    keywords: ['shell', 'mode', 'macos', 'mac', 'dock', 'menubar', 'switch'],
  }),
  Object.freeze({
    id: 'action:switch-shell-mode:ios',
    title: 'Switch to iOS Shell Mode',
    subtitle: 'Dynamic Island, Control Center & SpringBoard',
    action: 'switch-shell-mode:ios',
    keywords: ['shell', 'mode', 'ios', 'iphone', 'springboard', 'dynamic island', 'switch'],
  }),
  Object.freeze({
    id: 'action:switch-shell-mode:android',
    title: 'Switch to Android Shell Mode',
    subtitle: 'Notification Shade, App Drawer & 3-Button Nav',
    action: 'switch-shell-mode:android',
    keywords: ['shell', 'mode', 'android', 'drawer', 'shade', 'recents', 'switch'],
  }),
  Object.freeze({
    id: 'action:toggle-theme',
    title: 'Toggle Dark / Light Theme',
    subtitle: 'Quick Action — System Appearance',
    action: 'toggle-theme',
    keywords: ['toggle', 'theme', 'dark', 'light', 'appearance'],
  }),
  Object.freeze({
    id: 'action:toggle-dnd',
    title: 'Toggle Do Not Disturb',
    subtitle: 'Quick Action — Mute Notifications',
    action: 'toggle-dnd',
    keywords: ['toggle', 'dnd', 'do not disturb', 'mute', 'quiet', 'notifications'],
  }),
  Object.freeze({
    id: 'action:open-terminal',
    title: 'Open OmniTerm',
    subtitle: 'Launch Multi-Syntax Terminal',
    action: 'launch:com.omnios.terminal',
    appId: 'com.omnios.terminal',
    keywords: ['open', 'launch', 'terminal', 'omniterm', 'shell', 'cli', 'bash', 'cmd'],
  }),
  Object.freeze({
    id: 'action:open-files',
    title: 'Open OmniFiles',
    subtitle: 'Launch Cross-Platform File Manager',
    action: 'launch:com.omnios.files',
    appId: 'com.omnios.files',
    keywords: ['open', 'launch', 'files', 'omnifiles', 'finder', 'explorer'],
  }),
  Object.freeze({
    id: 'action:open-monitor',
    title: 'Open Activity Monitor',
    subtitle: 'Inspect Processes, Memory, Services & dmesg',
    action: 'launch:com.omnios.monitor',
    appId: 'com.omnios.monitor',
    keywords: ['open', 'launch', 'activity', 'monitor', 'task manager', 'processes', 'ps'],
  }),
  Object.freeze({
    id: 'action:open-apphub',
    title: 'Open App Hub',
    subtitle: 'Install & Launch 4-Platform Apps',
    action: 'launch:com.omnios.apphub',
    appId: 'com.omnios.apphub',
    keywords: ['open', 'launch', 'apphub', 'app store', 'packages', 'install'],
  }),
  Object.freeze({
    id: 'action:open-settings',
    title: 'Open System Settings',
    subtitle: 'Permissions, Registry, Defaults & Privacy',
    action: 'launch:com.omnios.settings',
    appId: 'com.omnios.settings',
    keywords: ['open', 'launch', 'settings', 'preferences', 'privacy', 'permissions'],
  }),
  Object.freeze({
    id: 'action:open-inspector',
    title: 'Open Binary Inspector',
    subtitle: 'Inspect APK, PE, Mach-O, IPA & WASM Binaries',
    action: 'launch:com.omnios.inspector',
    appId: 'com.omnios.inspector',
    keywords: ['open', 'launch', 'inspector', 'binary', 'hex', 'debugger'],
  }),
  Object.freeze({
    id: 'action:open-notes',
    title: 'Open OmniNotes',
    subtitle: 'Cross-Platform Notes & Text Editor',
    action: 'launch:com.omnios.notes',
    appId: 'com.omnios.notes',
    keywords: ['open', 'launch', 'notes', 'omninotes', 'editor', 'text'],
  }),
]);

function normalizeQuery(raw) {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (trimmed.length === 0) return '';
  return trimmed.length > MAX_QUERY_LENGTH ? trimmed.slice(0, MAX_QUERY_LENGTH) : trimmed;
}

function normalizeTypesFilter(types) {
  if (types === null || types === undefined || types === '') return null;
  let list;
  if (typeof types === 'string') {
    list = types.split(',');
  } else if (Array.isArray(types)) {
    list = types;
  } else if (types instanceof Set) {
    list = Array.from(types);
  } else {
    return null;
  }
  const set = new Set();
  for (const raw of list) {
    const clean = String(raw).trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(TYPE_ALIAS_MAP, clean)) {
      set.add(TYPE_ALIAS_MAP[clean]);
    }
  }
  return set.size > 0 ? set : null;
}

function isWordBoundaryMatch(haystack, needle) {
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    if (idx === 0) return true;
    const prev = haystack.charCodeAt(idx - 1);
    const isAlnum =
      (prev >= 48 && prev <= 57) ||
      (prev >= 65 && prev <= 90) ||
      (prev >= 97 && prev <= 122);
    if (!isAlnum) return true;
    idx = haystack.indexOf(needle, idx + 1);
  }
  return false;
}

function isSubsequence(needle, haystack) {
  if (needle.length < 3 || needle.length > 32 || haystack.length === 0) return false;
  let j = 0;
  for (let i = 0; i < haystack.length && j < needle.length; i += 1) {
    if (haystack.charCodeAt(i) === needle.charCodeAt(j)) {
      j += 1;
    }
  }
  return j === needle.length;
}

function flattenTextTerms(items) {
  const out = [];
  for (let i = 0; i < items.length; i += 1) {
    const val = items[i];
    if (val === null || val === undefined) continue;
    if (Array.isArray(val)) {
      for (let j = 0; j < val.length; j += 1) {
        if (val[j] !== null && val[j] !== undefined) {
          const s = String(val[j]).trim();
          if (s.length > 0) out.push(s);
        }
      }
    } else {
      const s = String(val).trim();
      if (s.length > 0) out.push(s);
    }
  }
  return out;
}

function scoreCandidate(qLower, tokens, primaryTerms, secondaryTerms, emptyDefaultScore) {
  if (qLower.length === 0) {
    return emptyDefaultScore;
  }

  let bestScore = 0;
  const primaryLower = primaryTerms.map((s) => s.toLowerCase());
  const secondaryLower = secondaryTerms.map((s) => s.toLowerCase());

  for (let i = 0; i < primaryLower.length; i += 1) {
    const term = primaryLower[i];
    if (term === qLower) {
      bestScore = Math.max(bestScore, 100);
    } else if (term.startsWith(qLower)) {
      bestScore = Math.max(bestScore, 80);
    } else if (isWordBoundaryMatch(term, qLower)) {
      bestScore = Math.max(bestScore, 65);
    } else if (term.includes(qLower)) {
      bestScore = Math.max(bestScore, 50);
    }
  }

  for (let i = 0; i < secondaryLower.length; i += 1) {
    const term = secondaryLower[i];
    if (term === qLower) {
      bestScore = Math.max(bestScore, 90);
    } else if (term.startsWith(qLower)) {
      bestScore = Math.max(bestScore, 70);
    } else if (isWordBoundaryMatch(term, qLower)) {
      bestScore = Math.max(bestScore, 55);
    } else if (term.includes(qLower)) {
      bestScore = Math.max(bestScore, 35);
    }
  }

  if (tokens.length > 1) {
    const combined = `${primaryLower.join(' ')} ${secondaryLower.join(' ')}`;
    let matchedTokens = 0;
    let tokenScore = 0;
    for (let i = 0; i < tokens.length; i += 1) {
      const tok = tokens[i];
      if (primaryLower.some((t) => t === tok)) {
        matchedTokens += 1;
        tokenScore += 22;
      } else if (primaryLower.some((t) => t.startsWith(tok))) {
        matchedTokens += 1;
        tokenScore += 18;
      } else if (combined.includes(tok)) {
        matchedTokens += 1;
        tokenScore += 12;
      }
    }
    if (matchedTokens === tokens.length) {
      bestScore = Math.max(bestScore, Math.min(95, 25 + tokenScore));
    }
  }

  if (bestScore === 0 && qLower.length >= 3 && qLower.length <= 32) {
    for (let i = 0; i < primaryLower.length; i += 1) {
      if (isSubsequence(qLower, primaryLower[i])) {
        bestScore = 15;
        break;
      }
    }
  }

  return bestScore;
}

function extractSpotlightTerms(spotlight) {
  if (!spotlight || typeof spotlight !== 'object') return [];
  return flattenTextTerms([
    spotlight.kMDItemDisplayName,
    spotlight.kMDItemKeywords,
    spotlight.kMDItemCategory,
    spotlight.kMDItemDescription,
    spotlight.kMDItemCFBundleIdentifier,
    spotlight.kMDItemExecutableArchitectures,
    spotlight.kMDItemContentType,
    spotlight.kMDItemPath,
  ]);
}

function decodeSpotlightXattr(rawBytes) {
  if (!rawBytes) return null;
  try {
    const text =
      typeof rawBytes === 'string'
        ? rawBytes
        : UTF8_DECODER.decode(
            rawBytes instanceof Uint8Array
              ? rawBytes
              : new Uint8Array(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength)
          );
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (err) {
    // Ignore corrupt/non-JSON xattr entries safely during search indexing.
    void err;
    return null;
  }
}

export class SpotlightSearch {
  constructor(os, options = {}) {
    this._os = os ?? null;
    this._maxVfsDepth =
      Number.isInteger(options.maxVfsDepth) && options.maxVfsDepth >= 0 ? options.maxVfsDepth : 6;
    this._maxVfsNodes =
      Number.isInteger(options.maxVfsNodes) && options.maxVfsNodes >= 0 ? options.maxVfsNodes : 500;
    this._defaultLimit =
      Number.isInteger(options.defaultLimit) && options.defaultLimit >= 0 ? options.defaultLimit : 25;
    this._maxLimit =
      Number.isInteger(options.maxLimit) && options.maxLimit >= 1 ? options.maxLimit : 100;

    this._spotlightCache = new Map();
    this._unsubSpotlight = null;

    this._attachListeners();
  }

  _attachListeners() {
    const bus = this._os?.eventBus ?? this._os?.kernel?.eventBus;
    if (!bus || typeof bus.on !== 'function') return;
    const handler = (payload) => {
      if (!payload || typeof payload !== 'object') return;
      const appId = typeof payload.appId === 'string' ? payload.appId : null;
      if (!appId) return;
      this._spotlightCache.set(appId, {
        appId,
        platform: payload.platform ?? 'macos',
        installDir: payload.installDir ?? null,
        spotlight: payload.spotlight && typeof payload.spotlight === 'object' ? { ...payload.spotlight } : {},
      });
    };
    const unsub = bus.on('spotlight:indexed', handler);
    this._unsubSpotlight =
      typeof unsub === 'function' ? unsub : () => bus.off?.('spotlight:indexed', handler);
  }

  dispose() {
    if (this._unsubSpotlight) {
      try {
        this._unsubSpotlight();
      } catch (err) {
        // Ignore eventBus teardown errors on dispose.
        void err;
      }
      this._unsubSpotlight = null;
    }
    this._spotlightCache.clear();
  }

  _collectApps(qLower, tokens, results) {
    const seenAppIds = new Set();

    // 1. Installed packages via PackageManager (including macOS Spotlight metadata)
    if (this._os?.pkgManager && typeof this._os.pkgManager.list === 'function') {
      let installed = [];
      try {
        installed = this._os.pkgManager.list();
      } catch (err) {
        // PackageManager may not be initialized yet (e.g., before boot).
        void err;
        installed = [];
      }
      for (const app of installed) {
        if (!app || typeof app.appId !== 'string') continue;
        seenAppIds.add(app.appId);
        const cached = this._spotlightCache.get(app.appId);
        const spotlight = app.metadata?.spotlight ?? cached?.spotlight ?? null;
        const displayName = spotlight?.kMDItemDisplayName || app.name || app.appId;
        const primary = flattenTextTerms([displayName, app.name, app.appId]);
        const secondary = flattenTextTerms([
          app.platform,
          app.format,
          app.arch,
          app.version,
          app.installDir,
          ...extractSpotlightTerms(spotlight),
        ]);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 75);
        if (score <= 0) continue;
        results.push({
          id: `app:${app.appId}`,
          type: 'app',
          title: displayName,
          subtitle: `${app.platform} app (${app.appId})`,
          score,
          platform: app.platform,
          appId: app.appId,
          metadata: {
            installed: true,
            builtin: false,
            format: app.format,
            arch: app.arch,
            version: app.version,
            installDir: app.installDir,
            ...(spotlight ? { spotlight } : {}),
          },
        });
      }
    }

    // 2. Built-in 7 system apps
    if (this._os?.systemApps && typeof this._os.systemApps.list === 'function') {
      let sysApps = [];
      try {
        sysApps = this._os.systemApps.list();
      } catch (err) {
        void err;
        sysApps = [];
      }
      for (const app of sysApps) {
        if (!app || typeof app.appId !== 'string') continue;
        seenAppIds.add(app.appId);
        const displayName = app.name || app.title || app.appId;
        const primary = flattenTextTerms([displayName, app.title, app.appId, ...(app.aliases ?? [])]);
        const secondary = flattenTextTerms([
          'system',
          app.category,
          app.description,
        ]);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 80);
        if (score <= 0) continue;
        results.push({
          id: `system:${app.appId}`,
          type: 'app',
          title: displayName,
          subtitle: app.description || `OmniOS System App (${app.category ?? 'system'})`,
          score,
          platform: 'system',
          appId: app.appId,
          metadata: {
            installed: true,
            builtin: true,
            aliases: Array.isArray(app.aliases) ? [...app.aliases] : [],
            category: app.category ?? 'system',
            icon: app.icon ?? null,
            runningPids: Array.isArray(app.runningPids) ? [...app.runningPids] : [],
          },
        });
      }
    }

    // 3. Uninstalled App Hub catalog entries
    if (this._os?.pkgManager && typeof this._os.pkgManager.getCatalog === 'function') {
      let catalog = [];
      try {
        catalog = this._os.pkgManager.getCatalog();
      } catch (err) {
        void err;
        catalog = [];
      }
      for (const entry of catalog) {
        if (!entry || typeof entry.appId !== 'string' || seenAppIds.has(entry.appId)) continue;
        seenAppIds.add(entry.appId);
        const primary = flattenTextTerms([entry.name, entry.appId, entry.catalogId]);
        const secondary = flattenTextTerms([
          entry.platform,
          entry.format,
          entry.description,
          entry.packagePath,
          entry.metadata?.category,
          entry.metadata?.arch,
          entry.metadata?.architectures,
          'catalog',
          'app hub',
        ]);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 55);
        if (score <= 0) continue;
        results.push({
          id: `catalog:${entry.catalogId ?? entry.appId}`,
          type: 'app',
          title: entry.name || entry.appId,
          subtitle: `${entry.platform} App Hub package (not installed)`,
          score: Math.max(1, score - 5),
          platform: entry.platform,
          appId: entry.appId,
          path: entry.packagePath ?? undefined,
          metadata: {
            installed: false,
            builtin: false,
            catalogId: entry.catalogId,
            format: entry.format,
            version: entry.version,
            description: entry.description,
            packagePath: entry.packagePath ?? null,
          },
        });
      }
    }
  }

  _collectVfsFiles(qLower, tokens, results) {
    const vfs = this._os?.vfs;
    if (!vfs || typeof vfs.readdir !== 'function') return;
    if (qLower.length === 0) return;

    const rootCtx = { uid: 0, gid: 0, withFileTypes: true };
    const xattrCtx = { uid: 0, gid: 0 };
    const visitedInodes = new Set();
    const queue = [];

    for (const root of VFS_SCAN_ROOTS) {
      queue.push({ dirPath: root, depth: 0 });
    }

    let nodesVisited = 0;

    while (queue.length > 0 && nodesVisited < this._maxVfsNodes) {
      const current = queue.shift();
      const { dirPath, depth } = current;
      if (dirPath === '/proc' || dirPath.startsWith('/proc/') || dirPath === '/dev' || dirPath.startsWith('/dev/')) {
        continue;
      }

      let entries;
      try {
        entries = vfs.readdir(dirPath, rootCtx);
      } catch (err) {
        // Directory may not exist yet or be inaccessible; skip safely.
        void err;
        continue;
      }

      if (!Array.isArray(entries)) continue;

      for (let i = 0; i < entries.length && nodesVisited < this._maxVfsNodes; i += 1) {
        const entry = entries[i];
        if (!entry || typeof entry.name !== 'string') continue;

        const fullPath = dirPath === '/' ? `/${entry.name}` : `${dirPath}/${entry.name}`;
        if (fullPath === '/proc' || fullPath === '/dev') continue;

        const inodeKey = entry.ino !== undefined ? `${entry.mount ?? 'root'}:${entry.ino}` : fullPath;
        if (visitedInodes.has(inodeKey)) continue;
        visitedInodes.add(inodeKey);
        nodesVisited += 1;

        let spotlight = null;
        if (
          entry.type === 'dir' &&
          (fullPath.startsWith('/apps/') || entry.name.endsWith('.app')) &&
          typeof vfs.getXattr === 'function'
        ) {
          try {
            const rawAttr = vfs.getXattr(fullPath, 'com.apple.metadata:omni_spotlight_json', xattrCtx);
            spotlight = decodeSpotlightXattr(rawAttr);
          } catch (err) {
            void err;
          }
        }

        const primary = flattenTextTerms([
          entry.name,
          spotlight?.kMDItemDisplayName,
        ]);
        const secondary = flattenTextTerms([
          fullPath,
          entry.type,
          ...extractSpotlightTerms(spotlight),
        ]);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 0);
        if (score > 0) {
          results.push({
            id: `file:${fullPath}`,
            type: 'file',
            title: spotlight?.kMDItemDisplayName || entry.name,
            subtitle: `${fullPath} (${entry.type}${typeof entry.size === 'number' ? `, ${entry.size}B` : ''})`,
            score,
            path: fullPath,
            metadata: {
              fileType: entry.type,
              size: entry.size ?? 0,
              ino: entry.ino ?? null,
              ...(spotlight ? { spotlight } : {}),
            },
          });
        }

        // Never follow symlinks during recursive search to guarantee cycle safety.
        if (entry.type === 'dir' && depth < this._maxVfsDepth) {
          queue.push({ dirPath: fullPath, depth: depth + 1 });
        }
      }
    }
  }

  _collectProcesses(qLower, tokens, results) {
    const pm = this._os?.processManager;
    if (!pm || typeof pm.list !== 'function') return;
    if (qLower.length === 0) return;

    let procs = [];
    try {
      procs = pm.list({ includeTerminated: false });
    } catch (err) {
      void err;
      procs = [];
    }

    for (const proc of procs) {
      if (!proc) continue;
      const pidStr = String(proc.pid);
      const primary = flattenTextTerms([proc.name, proc.appId, pidStr, `pid ${pidStr}`]);
      const secondary = flattenTextTerms([proc.platform, proc.arch, proc.state, 'process']);
      const score = scoreCandidate(qLower, tokens, primary, secondary, 0);
      if (score <= 0) continue;
      results.push({
        id: `process:${proc.pid}`,
        type: 'process',
        title: `${proc.name} (PID ${proc.pid})`,
        subtitle: `${proc.platform ?? 'system'} — ${proc.state} (${proc.appId ?? 'system'})`,
        score,
        platform: proc.platform ?? 'system',
        appId: proc.appId ?? undefined,
        pid: proc.pid,
        metadata: {
          state: proc.state,
          arch: proc.arch,
          uid: proc.uid,
          windowCount: proc.windowCount ?? 0,
        },
      });
    }
  }

  _collectSettings(qLower, tokens, results) {
    const store = this._os?.configStore;
    if (!store) return;

    if (store.system && typeof store.system.getAll === 'function') {
      let sysValues = {};
      try {
        sysValues = store.system.getAll() ?? {};
      } catch (err) {
        // Config store may not be initialized before boot.
        void err;
        sysValues = {};
      }
      for (const [key, value] of Object.entries(sysValues)) {
        const meta = SYSTEM_SETTINGS_CATALOG[key] ?? {
          title: key,
          description: `System setting ${key}`,
          keywords: [key],
        };
        const primary = flattenTextTerms([meta.title, key]);
        const secondary = flattenTextTerms([
          meta.description,
          meta.keywords,
          String(value),
          'settings',
          'config',
        ]);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 0);
        if (score <= 0) continue;
        results.push({
          id: `setting:${key}`,
          type: 'setting',
          title: meta.title,
          subtitle: `${key} = ${String(value)}`,
          score,
          key,
          value,
          metadata: {
            source: 'system',
            description: meta.description,
          },
        });
      }
    }

    if (qLower.length > 0 && store.defaults && typeof store.defaults.listDomains === 'function') {
      let domains = [];
      try {
        domains = store.defaults.listDomains();
      } catch (err) {
        void err;
        domains = [];
      }
      for (const domain of domains) {
        if (typeof domain !== 'string' || domain.length === 0) continue;
        const primary = flattenTextTerms([domain]);
        const secondary = flattenTextTerms(['defaults', 'plist', 'preferences', 'macos', 'apple']);
        const score = scoreCandidate(qLower, tokens, primary, secondary, 0);
        if (score <= 0) continue;
        results.push({
          id: `setting:defaults:${domain}`,
          type: 'setting',
          title: `Defaults: ${domain}`,
          subtitle: 'Apple NSUserDefaults / Plist Domain',
          score: Math.max(1, score - 5),
          key: domain,
          metadata: {
            source: 'defaults',
            domain,
          },
        });
      }
    }
  }

  _collectActions(qLower, tokens, results) {
    for (const act of QUICK_ACTIONS) {
      const primary = flattenTextTerms([act.title, act.action]);
      const secondary = flattenTextTerms([act.subtitle, act.keywords, act.appId, 'action']);
      const score = scoreCandidate(qLower, tokens, primary, secondary, 60);
      if (score <= 0) continue;
      results.push({
        id: act.id,
        type: 'action',
        title: act.title,
        subtitle: act.subtitle,
        score,
        action: act.action,
        ...(act.appId ? { appId: act.appId } : {}),
        metadata: {
          quickAction: true,
        },
      });
    }
  }

  query(rawQuery = '', options = {}) {
    const queryStr = normalizeQuery(rawQuery);
    const qLower = queryStr.toLowerCase();
    const tokens = qLower.length > 0 ? qLower.split(/\s+/).filter(Boolean) : [];

    const rawLimit = options?.limit;
    const parsedLimit =
      rawLimit === undefined || rawLimit === null || rawLimit === ''
        ? this._defaultLimit
        : Number(rawLimit);
    const limit = Number.isFinite(parsedLimit)
      ? Math.max(0, Math.min(this._maxLimit, Math.floor(parsedLimit)))
      : this._defaultLimit;

    const allowedTypes = normalizeTypesFilter(options?.types);
    const allResults = [];

    if (!allowedTypes || allowedTypes.has('app')) {
      this._collectApps(qLower, tokens, allResults);
    }
    if (!allowedTypes || allowedTypes.has('file')) {
      this._collectVfsFiles(qLower, tokens, allResults);
    }
    if (!allowedTypes || allowedTypes.has('process')) {
      this._collectProcesses(qLower, tokens, allResults);
    }
    if (!allowedTypes || allowedTypes.has('setting')) {
      this._collectSettings(qLower, tokens, allResults);
    }
    if (!allowedTypes || allowedTypes.has('action')) {
      this._collectActions(qLower, tokens, allResults);
    }

    allResults.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const pa = TYPE_PRIORITY[a.type] ?? 0;
      const pb = TYPE_PRIORITY[b.type] ?? 0;
      if (pb !== pa) return pb - pa;
      if (a.title !== b.title) return a.title < b.title ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });

    const sliced = allResults.slice(0, limit);
    const groups = {
      apps: [],
      files: [],
      processes: [],
      settings: [],
      actions: [],
    };
    for (let i = 0; i < sliced.length; i += 1) {
      const item = sliced[i];
      if (item.type === 'app') groups.apps.push(item);
      else if (item.type === 'file') groups.files.push(item);
      else if (item.type === 'process') groups.processes.push(item);
      else if (item.type === 'setting') groups.settings.push(item);
      else if (item.type === 'action') groups.actions.push(item);
    }

    return {
      query: queryStr,
      total: allResults.length,
      results: sliced,
      groups,
    };
  }
}

export function createSpotlightSearch(os, options = {}) {
  return new SpotlightSearch(os, options);
}
