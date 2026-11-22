/**
 * OmniOS Built-in System App: OmniFiles (`com.omnios.files`, F-068)
 * Unified cross-platform File Manager supporting Finder (macOS), Explorer (Windows C:\),
 * Android (/sdcard), iOS (/var/mobile/Documents), and POSIX (/) view modes.
 * Zero host filesystem access — all operations run strictly through `os.vfs` & `os.pathTranslator`.
 */

export const FILES_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.files',
  aliases: Object.freeze(['files', 'omnifiles']),
  name: 'OmniFiles',
  title: 'OmniFiles — Unified File Manager',
  platform: 'system',
  category: 'Utilities',
  icon: 'folder',
  description: 'Cross-platform Finder, Explorer C:\\, Android /sdcard & iOS Files browser',
});

export const FILES_VIEW_MODES = Object.freeze(['finder', 'explorer', 'android', 'ios', 'posix']);

const MODE_TO_PLATFORM = Object.freeze({
  finder: 'macos',
  explorer: 'windows',
  android: 'android',
  ios: 'ios',
  posix: 'posix',
});

const MODE_LABELS = Object.freeze({
  finder: 'macOS Finder',
  explorer: 'Windows Explorer (C:\\)',
  android: 'Android Files (/sdcard)',
  ios: 'iOS Files (/var/mobile)',
  posix: 'POSIX Root (/)',
});

const EXT_MIME = Object.freeze({
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.log': 'text/plain',
  '.json': 'application/json',
  '.html': 'text/html',
  '.xml': 'application/xml',
  '.apk': 'application/vnd.android.package-archive',
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.ipa': 'application/octet-stream',
  '.uapp': 'application/zip',
  '.wasm': 'application/wasm',
});

const FILES_MENU_BAR = Object.freeze([
  {
    id: 'files',
    label: 'OmniFiles',
    items: [
      { id: 'files.refresh', label: 'Refresh' },
      { id: 'files.up', label: 'Enclosing Folder' },
      { id: 'files.close', label: 'Close Window' },
    ],
  },
  {
    id: 'view',
    label: 'View Mode',
    items: [
      { id: 'view.finder', label: 'macOS Finder' },
      { id: 'view.explorer', label: 'Windows Explorer (C:\\)' },
      { id: 'view.android', label: 'Android (/sdcard)' },
      { id: 'view.ios', label: 'iOS (/var/mobile)' },
      { id: 'view.posix', label: 'POSIX (/)' },
    ],
  },
]);

function parentOf(canonicalPath) {
  if (!canonicalPath || canonicalPath === '/') return '/';
  const trimmed = canonicalPath.endsWith('/') ? canonicalPath.slice(0, -1) : canonicalPath;
  const idx = trimmed.lastIndexOf('/');
  return idx <= 0 ? '/' : trimmed.slice(0, idx);
}

function joinCanonical(dir, name) {
  const cleanName = String(name ?? '').replace(/^\/+/, '');
  if (!cleanName) return dir;
  return dir === '/' ? `/${cleanName}` : `${dir}/${cleanName}`;
}

function getExtension(p) {
  const idx = p.lastIndexOf('.');
  const slash = p.lastIndexOf('/');
  if (idx <= slash) return '';
  return p.slice(idx).toLowerCase();
}

export function createFilesExecutionContext(os, pcb, launchOpts = {}) {
  const initialMode = FILES_VIEW_MODES.includes(launchOpts.viewMode) ? launchOpts.viewMode : 'finder';
  let initialPath = '/home/user';
  if (typeof launchOpts.cwd === 'string' && launchOpts.cwd.length > 0) {
    initialPath = launchOpts.cwd;
  } else if (typeof launchOpts.intent?.uri === 'string' && launchOpts.intent.uri.startsWith('file://')) {
    initialPath = launchOpts.intent.uri.slice('file://'.length) || '/home/user';
  } else if (typeof launchOpts.intent?.extras?.path === 'string') {
    initialPath = launchOpts.intent.extras.path;
  }

  const state = {
    viewMode: initialMode,
    currentPath: '/home/user',
    platformPath: '/Users/user',
    entries: [],
    selectedEntry: null,
    previewContent: null,
    previewBinary: false,
    lastOpenWithResult: null,
    statusMessage: 'Ready',
    errorMessage: null,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x2000;
  let lastSyscall = 'vfs.readdir';
  let windowId = null;
  let pendingAsync = Promise.resolve();
  let vfsUnsub = null;

  const vfsCtx = () => ({
    uid: pcb.uid,
    gid: pcb.gid,
    cwd: state.currentPath,
    platform: MODE_TO_PLATFORM[state.viewMode] ?? 'posix',
  });

  const translateToPlatform = (canonical) => {
    const plat = MODE_TO_PLATFORM[state.viewMode] ?? 'posix';
    try {
      return os.pathTranslator.toPlatform(canonical, plat);
    } catch (_err) {
      return canonical;
    }
  };

  const resolveInputPath = (rawPath) => {
    const plat = MODE_TO_PLATFORM[state.viewMode] ?? 'posix';
    const raw = String(rawPath ?? '');
    const inferredPlat = /^[A-Za-z]:[\\/]/.test(raw) ? 'windows' : plat;
    const res = os.pathTranslator.toCanonical(raw, {
      platform: inferredPlat,
      cwd: state.currentPath,
    });
    return res.canonicalPath;
  };

  const refreshListing = () => {
    if (!os.vfs?.isReady) {
      state.entries = [];
      state.errorMessage = 'VFS not mounted';
      return;
    }
    try {
      const items = os.vfs.readdir(state.currentPath, vfsCtx());
      state.entries = items
        .map((e) => ({
          name: e.name,
          path: joinCanonical(state.currentPath, e.name),
          type: e.type,
          size: Number(e.size ?? 0),
          mode: e.mode,
          uid: e.uid,
          gid: e.gid,
          target: e.target ?? null,
        }))
        .sort((a, b) => {
          if (a.type === 'dir' && b.type !== 'dir') return -1;
          if (a.type !== 'dir' && b.type === 'dir') return 1;
          return a.name.localeCompare(b.name);
        });
      state.platformPath = translateToPlatform(state.currentPath);
      state.errorMessage = null;
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
    }
  };

  const rmRecursive = (targetPath, depth = 0) => {
    if (depth > 32) throw new Error('Max recursion depth exceeded');
    const ctx = vfsCtx();
    const st = os.vfs.lstat(targetPath, ctx);
    if (st.type !== 'dir') {
      os.vfs.unlink(targetPath, ctx);
      return;
    }
    const children = os.vfs.readdir(targetPath, ctx);
    for (const c of children) {
      const cp = joinCanonical(targetPath, c.name);
      if (c.type === 'dir') rmRecursive(cp, depth + 1);
      else os.vfs.unlink(cp, ctx);
    }
    os.vfs.rmdir(targetPath, ctx);
  };

  const buildSidebarPlaces = () => {
    const places = [
      { id: 'place-home', label: 'Home', path: '/home/user' },
      { id: 'place-docs', label: 'Documents', path: '/home/user/Documents' },
      { id: 'place-downloads', label: 'Downloads', path: '/home/user/Downloads' },
      { id: 'place-desktop', label: 'Desktop', path: '/home/user/Desktop' },
      { id: 'place-pictures', label: 'Pictures', path: '/home/user/Pictures' },
      { id: 'place-packages', label: 'Packages', path: '/packages' },
      { id: 'place-apps', label: 'Apps', path: '/apps' },
      { id: 'place-tmp', label: 'Temp (/tmp)', path: '/tmp' },
      { id: 'place-proc', label: 'Proc (/proc)', path: '/proc' },
    ];
    return places.map((p) => ({
      ...p,
      platformPath: translateToPlatform(p.path),
    }));
  };

  const buildUiTree = () => ({
    id: 'omnifiles-root',
    type: 'container',
    role: 'file-manager',
    props: {
      appId: FILES_APP_DESCRIPTOR.appId,
      viewMode: state.viewMode,
      modeLabel: MODE_LABELS[state.viewMode],
      currentPath: state.currentPath,
      platformPath: state.platformPath,
      entryCount: state.entries.length,
      selectedEntry: state.selectedEntry,
      statusMessage: state.statusMessage,
      errorMessage: state.errorMessage,
    },
    children: [
      {
        id: 'files-toolbar',
        type: 'toolbar',
        props: { currentPath: state.currentPath, platformPath: state.platformPath },
        children: [
          { id: 'files-up', type: 'button', props: { label: 'Up', action: 'up' } },
          { id: 'files-refresh', type: 'button', props: { label: 'Refresh', action: 'refresh' } },
          ...FILES_VIEW_MODES.map((m) => ({
            id: `mode-${m}`,
            type: 'button',
            props: {
              label: MODE_LABELS[m],
              action: 'set_mode',
              mode: m,
              active: state.viewMode === m,
            },
          })),
          {
            id: 'files-path-bar',
            type: 'text',
            props: {
              text: state.platformPath,
              canonicalPath: state.currentPath,
              platformPath: state.platformPath,
            },
          },
        ],
      },
      {
        id: 'files-sidebar',
        type: 'list',
        props: { title: 'Locations' },
        children: buildSidebarPlaces().map((place) => ({
          id: place.id,
          type: 'button',
          props: {
            label: place.label,
            action: 'navigate',
            path: place.path,
            platformPath: place.platformPath,
            active: state.currentPath === place.path,
          },
        })),
      },
      {
        id: 'files-entries',
        type: 'list',
        props: { count: state.entries.length, viewMode: state.viewMode },
        children: state.entries.map((entry) => ({
          id: `entry:${entry.name}`,
          type: 'listitem',
          props: {
            name: entry.name,
            path: entry.path,
            entryType: entry.type,
            size: entry.size,
            mode: entry.mode,
            target: entry.target,
            selected: state.selectedEntry?.path === entry.path,
          },
        })),
      },
      {
        id: 'files-preview',
        type: 'panel',
        props: {
          selectedPath: state.selectedEntry?.path ?? null,
          selectedType: state.selectedEntry?.type ?? null,
          binary: state.previewBinary,
          content: state.previewContent,
          lastOpenWithResult: state.lastOpenWithResult,
        },
        children: state.previewContent !== null
          ? [{ id: 'files-preview-text', type: 'text', props: { text: state.previewContent } }]
          : [],
      },
      {
        id: 'files-status',
        type: 'statusbar',
        props: {
          text: state.errorMessage ? `Error: ${state.errorMessage}` : state.statusMessage,
          error: state.errorMessage,
        },
      },
    ],
  });

  const renderSurface = () => {
    if (disposed || !windowId || !os.compositor) return;
    if (!os.compositor.getWindow(windowId)) return;
    try {
      os.compositor.updateSurface(windowId, {
        title: `OmniFiles (${MODE_LABELS[state.viewMode]}) — ${state.platformPath}`,
        menuBar: FILES_MENU_BAR,
        uiTree: buildUiTree(),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'files-app', `Failed to update OmniFiles surface: ${err.message}`);
    }
  };

  const openFilePreview = (canonicalPath) => {
    const ctx = vfsCtx();
    const st = os.vfs.lstat(canonicalPath, ctx);
    state.selectedEntry = {
      path: canonicalPath,
      name: canonicalPath.split('/').pop() || '/',
      type: st.type,
      size: st.size,
      mode: st.mode,
      target: st.target ?? null,
    };
    if (st.type === 'file' || st.type === 'symlink') {
      const bytes = os.vfs.readFile(canonicalPath, ctx);
      const slice = bytes.subarray(0, 16384);
      let isBinary = false;
      for (let i = 0; i < Math.min(slice.length, 512); i += 1) {
        if (slice[i] === 0) {
          isBinary = true;
          break;
        }
      }
      state.previewBinary = isBinary;
      state.previewContent = isBinary
        ? `[Binary file, ${bytes.byteLength} bytes, magic: ${Buffer.from(slice.subarray(0, 16)).toString('hex')}]`
        : Buffer.from(slice).toString('utf8');
      state.statusMessage = `Loaded ${canonicalPath} (${bytes.byteLength} bytes)`;
    } else {
      state.previewBinary = false;
      state.previewContent = null;
    }
  };

  const dispose = (reason = 'disposed') => {
    if (disposed) return;
    disposed = true;
    exited = true;
    if (typeof vfsUnsub === 'function') {
      vfsUnsub();
      vfsUnsub = null;
    }
    if (windowId && os.compositor?.getWindow(windowId)) {
      try {
        os.compositor.closeWindow(windowId, { notifyProcess: false, reason });
      } catch (err) {
        os.kernel?.log('debug', 'files-app', `Window already closed on dispose: ${err.message}`);
      }
    }
  };

  const handleEvent = (event) => {
    if (!event || typeof event !== 'object' || disposed) return;
    pc += 2;
    instructionsExecuted += 5;

    if (event.type === 'window_close' || event.type === 'terminate') {
      lastSyscall = 'window_close';
      dispose(event.type);
      return;
    }

    try {
      if (event.type === 'menu_action') {
        const aid = event.actionId ?? event.itemId ?? event.id ?? '';
        if (aid === 'files.refresh') {
          refreshListing();
          renderSurface();
        } else if (aid === 'files.up') {
          state.currentPath = parentOf(state.currentPath);
          refreshListing();
          renderSurface();
        } else if (aid === 'files.close') {
          lastSyscall = 'menu_close';
          dispose('menu_close');
        } else if (aid.startsWith('view.')) {
          const mode = aid.slice('view.'.length);
          if (FILES_VIEW_MODES.includes(mode)) {
            state.viewMode = mode;
            state.platformPath = translateToPlatform(state.currentPath);
            state.statusMessage = `Switched view to ${MODE_LABELS[mode]}`;
            renderSurface();
          }
        }
        return;
      }

      if (event.type === 'intent') {
        const uri = event.intent?.uri ?? '';
        const target = uri.startsWith('file://') ? uri.slice('file://'.length) : event.intent?.extras?.path;
        if (target) {
          const canon = resolveInputPath(target);
          const st = os.vfs.stat(canon, vfsCtx());
          if (st.type === 'dir') {
            state.currentPath = canon;
            refreshListing();
          } else {
            state.currentPath = parentOf(canon);
            refreshListing();
            openFilePreview(canon);
          }
          renderSurface();
        }
        return;
      }

      const action = event.action ?? '';
      const targetId = event.targetId ?? '';

      if (action === 'set_mode' || targetId.startsWith('mode-')) {
        const mode = event.mode ?? targetId.slice('mode-'.length);
        if (FILES_VIEW_MODES.includes(mode)) {
          state.viewMode = mode;
          state.platformPath = translateToPlatform(state.currentPath);
          state.statusMessage = `View mode: ${MODE_LABELS[mode]}`;
          lastSyscall = `files.mode:${mode}`;
          renderSurface();
        }
        return;
      }

      if (action === 'up' || action === 'go_up' || targetId === 'files-up') {
        state.currentPath = parentOf(state.currentPath);
        state.selectedEntry = null;
        state.previewContent = null;
        lastSyscall = 'vfs.chdir';
        refreshListing();
        state.statusMessage = `Navigated to ${state.currentPath}`;
        renderSurface();
        return;
      }

      if (action === 'refresh' || targetId === 'files-refresh') {
        lastSyscall = 'vfs.readdir';
        refreshListing();
        state.statusMessage = 'Refreshed';
        renderSurface();
        return;
      }

      if (action === 'navigate' || action === 'open_dir') {
        const canon = resolveInputPath(event.path ?? event.value ?? '/home/user');
        const st = os.vfs.stat(canon, vfsCtx());
        if (st.type === 'dir') {
          state.currentPath = canon;
          state.selectedEntry = null;
          state.previewContent = null;
          lastSyscall = 'vfs.readdir';
          refreshListing();
          state.statusMessage = `Opened ${canon}`;
        } else {
          state.currentPath = parentOf(canon);
          refreshListing();
          openFilePreview(canon);
        }
        renderSurface();
        return;
      }

      if (targetId.startsWith('entry:')) {
        const name = targetId.slice('entry:'.length);
        const fullPath = joinCanonical(state.currentPath, name);
        const st = os.vfs.stat(fullPath, vfsCtx());
        if (st.type === 'dir') {
          state.currentPath = fullPath;
          state.selectedEntry = null;
          state.previewContent = null;
          refreshListing();
          state.statusMessage = `Entered ${fullPath}`;
        } else {
          openFilePreview(fullPath);
        }
        lastSyscall = 'files.select';
        renderSurface();
        return;
      }

      if (action === 'mkdir') {
        const target = event.path ? resolveInputPath(event.path) : joinCanonical(state.currentPath, event.name);
        os.vfs.mkdir(target, { ...vfsCtx(), recursive: true });
        lastSyscall = 'vfs.mkdir';
        refreshListing();
        state.statusMessage = `Created directory ${target}`;
        renderSurface();
        return;
      }

      if (action === 'create_file' || action === 'write_file') {
        const target = event.path ? resolveInputPath(event.path) : joinCanonical(state.currentPath, event.name);
        const content = event.content ?? event.data ?? '';
        os.vfs.writeFile(target, content, vfsCtx());
        lastSyscall = 'vfs.writeFile';
        refreshListing();
        openFilePreview(target);
        state.statusMessage = `Saved ${target}`;
        renderSurface();
        return;
      }

      if (action === 'read_file' || action === 'preview') {
        const target = event.path ? resolveInputPath(event.path) : joinCanonical(state.currentPath, event.name);
        lastSyscall = 'vfs.readFile';
        openFilePreview(target);
        renderSurface();
        return;
      }

      if (action === 'delete' || action === 'remove') {
        const target = event.path ? resolveInputPath(event.path) : joinCanonical(state.currentPath, event.name);
        const st = os.vfs.lstat(target, vfsCtx());
        if (st.type === 'dir') {
          if (event.recursive) rmRecursive(target);
          else os.vfs.rmdir(target, vfsCtx());
        } else {
          os.vfs.unlink(target, vfsCtx());
        }
        if (state.selectedEntry?.path === target) {
          state.selectedEntry = null;
          state.previewContent = null;
        }
        lastSyscall = 'vfs.unlink';
        refreshListing();
        state.statusMessage = `Deleted ${target}`;
        renderSurface();
        return;
      }

      if (action === 'rename' || action === 'move') {
        const oldPath = resolveInputPath(event.oldPath ?? event.from ?? joinCanonical(state.currentPath, event.name));
        const newPath = resolveInputPath(event.newPath ?? event.to ?? joinCanonical(state.currentPath, event.newName));
        os.vfs.rename(oldPath, newPath, vfsCtx());
        lastSyscall = 'vfs.rename';
        refreshListing();
        state.statusMessage = `Renamed ${oldPath} -> ${newPath}`;
        renderSurface();
        return;
      }

      if (action === 'symlink') {
        const target = String(event.target ?? '');
        const linkPath = event.linkPath
          ? resolveInputPath(event.linkPath)
          : joinCanonical(state.currentPath, event.name);
        os.vfs.symlink(target, linkPath, vfsCtx());
        lastSyscall = 'vfs.symlink';
        refreshListing();
        state.statusMessage = `Created symlink ${linkPath} -> ${target}`;
        renderSurface();
        return;
      }

      if (action === 'open_with') {
        const target = event.path
          ? resolveInputPath(event.path)
          : (state.selectedEntry?.path ?? joinCanonical(state.currentPath, event.name ?? ''));
        const ext = getExtension(target);
        const mimeType = EXT_MIME[ext] ?? null;
        lastSyscall = 'intent.dispatch';
        state.statusMessage = `Dispatching Open-With for ${target}...`;
        renderSurface();

        const dispatchRes = os.intentRouter.dispatch({
          action: event.intentAction ?? 'view',
          uri: `file://${target}`,
          extension: ext || null,
          mimeType,
          preferredAppId: event.preferredAppId ?? null,
          sourcePid: pcb.pid,
        });

        pendingAsync = Promise.resolve(dispatchRes)
          .then((resolved) => {
            state.lastOpenWithResult = resolved;
            state.statusMessage = `Open-With ${target}: ${resolved.status}`;
            if (!disposed) renderSurface();
          })
          .catch((err) => {
            state.errorMessage = err?.message ?? String(err);
            if (!disposed) renderSurface();
          });
      }
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
      renderSurface();
    }
  };

  // Initialize starting directory cleanly
  try {
    const startCanon = resolveInputPath(initialPath);
    if (os.vfs?.isReady) {
      const st = os.vfs.stat(startCanon, vfsCtx());
      if (st.type === 'dir') {
        state.currentPath = startCanon;
      } else {
        state.currentPath = parentOf(startCanon);
      }
    }
  } catch (err) {
    state.currentPath = '/home/user';
    state.errorMessage = err?.message ?? null;
  }

  refreshListing();

  const win = os.compositor.createWindow(pcb.pid, {
    appId: FILES_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `OmniFiles (${MODE_LABELS[state.viewMode]}) — ${state.platformPath}`,
    icon: FILES_APP_DESCRIPTOR.icon,
    width: 820,
    height: 540,
    chromeStyle: 'unified',
    menuBar: FILES_MENU_BAR,
    uiTree: buildUiTree(),
  });
  windowId = win.windowId;

  if (os.eventBus && typeof os.eventBus.on === 'function') {
    vfsUnsub = os.eventBus.on('vfs:changed', () => {
      if (disposed) return;
      refreshListing();
      dirty = true;
    });
  }

  return {
    windowId,
    flushPending: () => pendingAsync,
    step(budget = 100) {
      void budget;
      if (dirty && !disposed) {
        renderSurface();
      }
      if (exited || disposed) {
        return { status: 'EXITED', exitCode: 0, instructionsExecuted: 1 };
      }
      return { status: 'BLOCKED', waitReason: 'ui_event', instructionsExecuted: 1 };
    },
    deliverEvent(event) {
      handleEvent(event);
    },
    getDebugState() {
      return {
        arch: 'native',
        appId: FILES_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ffe0000,
        registers: {
          r0: state.entries.length,
          r1: FILES_VIEW_MODES.indexOf(state.viewMode),
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ffe0000,
        windowId,
        stateSummary: {
          viewMode: state.viewMode,
          currentPath: state.currentPath,
          platformPath: state.platformPath,
          entryCount: state.entries.length,
          selectedPath: state.selectedEntry?.path ?? null,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
