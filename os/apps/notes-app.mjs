/**
 * OmniOS Built-in System App: OmniNotes (`com.omnios.notes`, F-072)
 * Cross-platform note editor persisting directly to VFS `/home/user/Documents/` (zero host filesystem access),
 * integrated with `SharedClipboard` (Copy/Paste) and `IntentRouter` (Share + incoming ACTION_SEND / .txt / .md).
 */

export const NOTES_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.notes',
  aliases: Object.freeze(['notes', 'omninotes']),
  name: 'OmniNotes',
  title: 'OmniNotes — Cross-Platform Notes',
  platform: 'system',
  category: 'Productivity',
  icon: 'notes',
  description: 'VFS-backed cross-platform notes editor with Shared Clipboard and Universal Share Sheet',
});

const NOTES_DIR = '/home/user/Documents';

const NOTES_MENU_BAR = Object.freeze([
  {
    id: 'notes',
    label: 'OmniNotes',
    items: [
      { id: 'notes.new', label: 'New Note' },
      { id: 'notes.save', label: 'Save Note' },
      { id: 'notes.share', label: 'Share Note...' },
      { id: 'notes.close', label: 'Close Window' },
    ],
  },
  {
    id: 'edit',
    label: 'Edit',
    items: [
      { id: 'edit.copy', label: 'Copy to Shared Clipboard' },
      { id: 'edit.paste', label: 'Paste from Shared Clipboard' },
    ],
  },
]);

function sanitizeNoteFilename(rawName, fallback = 'untitled.txt') {
  let cleaned = String(rawName ?? fallback).trim();
  // Strip URI scheme prefixes (e.g. file://)
  cleaned = cleaned.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, '');
  // Strip NUL and ASCII control chars
  cleaned = cleaned.replace(/[\x00-\x1f\x7f]/g, '');
  // Replace path separators and any traversal sequences ("..")
  cleaned = cleaned.replace(/[/\\]+/g, '_').replace(/\.\.+/g, '_');
  // Strip leading dots and surrounding whitespace
  cleaned = cleaned.replace(/^\.+/, '').trim();
  if (!cleaned || /^[_.\s-]+$/.test(cleaned)) return fallback;
  if (cleaned.length > 128) cleaned = cleaned.slice(0, 128);
  if (!cleaned.includes('.')) return `${cleaned}.txt`;
  return cleaned;
}

function resolveNotePath(rawPathOrName) {
  const s = String(rawPathOrName ?? '').trim();
  if (!s) return `${NOTES_DIR}/untitled.txt`;
  if (s.startsWith('file://')) return s.slice('file://'.length);
  if (s.startsWith('/')) return s;
  return `${NOTES_DIR}/${sanitizeNoteFilename(s)}`;
}

export function createNotesExecutionContext(os, pcb, launchOpts = {}) {
  const state = {
    notes: [],
    currentPath: `${NOTES_DIR}/untitled.txt`,
    filename: 'untitled.txt',
    content: '',
    dirty: false,
    lastShareResult: null,
    receivedIntents: [],
    statusMessage: 'Ready',
    errorMessage: null,
  };

  let exited = false;
  let disposed = false;
  let surfaceDirty = false;
  let instructionsExecuted = 0;
  let pc = 0x7000;
  let lastSyscall = 'vfs.readdir';
  let windowId = null;
  let pendingAsync = Promise.resolve();
  let vfsUnsub = null;

  const vfsCtx = () => ({ uid: pcb.uid, gid: pcb.gid, cwd: NOTES_DIR });

  const ensureDocumentsDir = () => {
    if (!os.vfs?.isReady) return;
    try {
      os.vfs.stat(NOTES_DIR, vfsCtx());
    } catch (_statErr) {
      try {
        os.vfs.mkdir(NOTES_DIR, { ...vfsCtx(), recursive: true });
      } catch (mkErr) {
        os.kernel?.log('warn', 'notes-app', `Failed creating ${NOTES_DIR}: ${mkErr.message}`);
      }
    }
  };

  const refreshNotesList = () => {
    if (!os.vfs?.isReady) {
      state.notes = [];
      return;
    }
    ensureDocumentsDir();
    try {
      const entries = os.vfs.readdir(NOTES_DIR, vfsCtx());
      state.notes = entries
        .filter((e) => e.type === 'file' && (e.name.endsWith('.txt') || e.name.endsWith('.md')))
        .map((e) => ({
          name: e.name,
          path: `${NOTES_DIR}/${e.name}`,
          size: Number(e.size ?? 0),
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
    }
  };

  const openNote = (pathOrName) => {
    const fullPath = resolveNotePath(pathOrName);
    const text = os.vfs.readFile(fullPath, { ...vfsCtx(), encoding: 'utf8' });
    state.currentPath = fullPath;
    state.filename = fullPath.split('/').pop() || 'untitled.txt';
    state.content = text;
    state.dirty = false;
    state.errorMessage = null;
    state.statusMessage = `Opened ${fullPath}`;
    lastSyscall = 'vfs.readFile';
  };

  const saveCurrentNote = (overrideName = null, overrideContent = null) => {
    ensureDocumentsDir();
    if (overrideName !== null && overrideName !== undefined && String(overrideName).trim().length > 0) {
      const target = resolveNotePath(overrideName);
      state.currentPath = target;
      state.filename = target.split('/').pop() || 'untitled.txt';
    }
    if (overrideContent !== null && overrideContent !== undefined) {
      state.content = String(overrideContent);
    }
    os.vfs.writeFile(state.currentPath, state.content, vfsCtx());
    state.dirty = false;
    state.errorMessage = null;
    state.statusMessage = `Saved ${state.currentPath} (${Buffer.byteLength(state.content, 'utf8')} bytes)`;
    lastSyscall = 'vfs.writeFile';
    refreshNotesList();
  };

  const applyIncomingIntent = (intent) => {
    if (!intent || typeof intent !== 'object') return;
    state.receivedIntents.push({
      action: intent.action ?? null,
      uri: intent.uri ?? null,
      mimeType: intent.mimeType ?? null,
      ts: new Date().toISOString(),
    });
    const action = String(intent.action ?? '').toLowerCase();
    const extras = intent.extras && typeof intent.extras === 'object' ? intent.extras : {};

    if (action === 'send' || action === 'android.intent.action.send') {
      const sharedText =
        extras['android.intent.extra.TEXT'] ??
        extras.text ??
        extras.body ??
        intent.uri ??
        '';
      const defaultSharedName = `shared-note-${Date.now()}.txt`;
      const rawSharedTitle =
        typeof extras.title === 'string' && extras.title.trim().length > 0
          ? extras.title
          : typeof extras.filename === 'string' && extras.filename.trim().length > 0
            ? extras.filename
            : defaultSharedName;
      // Confine untrusted ACTION_SEND filenames strictly inside NOTES_DIR (/home/user/Documents)
      const safeName = sanitizeNoteFilename(rawSharedTitle, 'shared-note.txt');
      const targetPath = `${NOTES_DIR}/${safeName}`;
      state.currentPath = targetPath;
      state.filename = safeName;
      state.content = String(sharedText);
      try {
        saveCurrentNote(null, state.content);
        state.statusMessage = `Received shared note -> ${state.currentPath}`;
      } catch (err) {
        state.dirty = true;
        state.errorMessage = err?.message ?? String(err);
      }
      return;
    }

    const fileTarget =
      (typeof intent.uri === 'string' && intent.uri.startsWith('file://') ? intent.uri.slice('file://'.length) : null) ??
      extras.path ??
      null;
    if (fileTarget) {
      try {
        openNote(fileTarget);
      } catch (err) {
        state.currentPath = resolveNotePath(fileTarget);
        state.filename = state.currentPath.split('/').pop() || 'untitled.txt';
        state.content = '';
        state.errorMessage = err?.message ?? String(err);
      }
    }
  };

  const buildUiTree = () => ({
    id: 'omninotes-root',
    type: 'container',
    role: 'notes-editor',
    props: {
      appId: NOTES_APP_DESCRIPTOR.appId,
      notesDir: NOTES_DIR,
      currentPath: state.currentPath,
      filename: state.filename,
      content: state.content,
      dirty: state.dirty,
      noteCount: state.notes.length,
      lastShareResult: state.lastShareResult,
      receivedIntentsCount: state.receivedIntents.length,
      statusMessage: state.statusMessage,
      errorMessage: state.errorMessage,
    },
    children: [
      {
        id: 'notes-toolbar',
        type: 'toolbar',
        props: { filename: state.filename, dirty: state.dirty },
        children: [
          { id: 'notes-new-btn', type: 'button', props: { label: 'New', action: 'new_note' } },
          { id: 'notes-save-btn', type: 'button', props: { label: 'Save', action: 'save' } },
          { id: 'notes-copy-btn', type: 'button', props: { label: 'Copy', action: 'copy' } },
          { id: 'notes-paste-btn', type: 'button', props: { label: 'Paste', action: 'paste' } },
          { id: 'notes-share-btn', type: 'button', props: { label: 'Share', action: 'share' } },
        ],
      },
      {
        id: 'notes-list',
        type: 'list',
        props: { count: state.notes.length },
        children: state.notes.map((n) => ({
          id: `note:${n.name}`,
          type: 'listitem',
          props: {
            name: n.name,
            path: n.path,
            size: n.size,
            active: n.path === state.currentPath,
          },
        })),
      },
      {
        id: 'note-title',
        type: 'input',
        props: { value: state.filename, placeholder: 'note-name.txt' },
      },
      {
        id: 'note-editor',
        type: 'textarea',
        props: { value: state.content, placeholder: 'Write your cross-platform note...' },
      },
      {
        id: 'notes-status',
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
        title: `OmniNotes — ${state.filename}${state.dirty ? ' *' : ''}`,
        menuBar: NOTES_MENU_BAR,
        uiTree: buildUiTree(),
      });
      surfaceDirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'notes-app', `Failed to update OmniNotes surface: ${err.message}`);
    }
  };

  const triggerShare = (preferredAppId = null) => {
    lastSyscall = 'intent.dispatch:send';
    state.statusMessage = 'Sharing note via Universal Intent Router...';
    renderSurface();

    const res = os.intentRouter.dispatch({
      action: 'send',
      mimeType: 'text/plain',
      extras: {
        text: state.content,
        'android.intent.extra.TEXT': state.content,
        title: state.filename,
        path: state.currentPath,
      },
      preferredAppId,
      sourcePid: pcb.pid,
    });

    pendingAsync = Promise.resolve(res)
      .then((resolved) => {
        state.lastShareResult = resolved;
        state.errorMessage = null;
        state.statusMessage = `Share result: ${resolved.status}${resolved.targetAppId ? ` (${resolved.targetAppId})` : ''}`;
        if (!disposed) renderSurface();
      })
      .catch((err) => {
        state.errorMessage = err?.message ?? String(err);
        if (!disposed) renderSurface();
      });
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
        os.kernel?.log('debug', 'notes-app', `Window already closed on dispose: ${err.message}`);
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
      if (event.type === 'intent') {
        applyIncomingIntent(event.intent ?? event);
        renderSurface();
        return;
      }

      if (event.type === 'menu_action') {
        const aid = event.actionId ?? event.itemId ?? event.id ?? '';
        if (aid === 'notes.new') {
          state.filename = `note-${Date.now()}.txt`;
          state.currentPath = `${NOTES_DIR}/${state.filename}`;
          state.content = '';
          state.dirty = true;
          renderSurface();
        } else if (aid === 'notes.save') {
          saveCurrentNote();
          renderSurface();
        } else if (aid === 'notes.share') {
          triggerShare();
        } else if (aid === 'notes.close') {
          lastSyscall = 'menu_close';
          dispose('menu_close');
        } else if (aid === 'edit.copy') {
          os.clipboard.set({ text: state.content, sourceAppId: NOTES_APP_DESCRIPTOR.appId });
          state.statusMessage = 'Copied note to Shared Clipboard';
          renderSurface();
        } else if (aid === 'edit.paste') {
          const clipText = os.clipboard.get('text/plain');
          if (typeof clipText === 'string' && clipText.length > 0) {
            state.content += clipText;
            state.dirty = true;
            state.statusMessage = 'Pasted from Shared Clipboard';
            renderSurface();
          }
        }
        return;
      }

      if (event.type === 'input' || event.type === 'change') {
        if (event.targetId === 'note-title') {
          const clean = sanitizeNoteFilename(event.value);
          state.filename = clean;
          state.currentPath = `${NOTES_DIR}/${clean}`;
          state.dirty = true;
          renderSurface();
        } else {
          state.content = String(event.value ?? '');
          state.dirty = true;
          renderSurface();
        }
        return;
      }

      const action = event.action ?? '';
      const targetId = event.targetId ?? '';

      if (action === 'new_note' || targetId === 'notes-new-btn') {
        const name = event.filename ? sanitizeNoteFilename(event.filename) : `note-${Date.now()}.txt`;
        state.filename = name;
        state.currentPath = `${NOTES_DIR}/${name}`;
        state.content = event.content !== undefined ? String(event.content) : '';
        state.dirty = true;
        if (event.save) {
          saveCurrentNote(state.currentPath, state.content);
        } else {
          state.statusMessage = `New note: ${name}`;
        }
        renderSurface();
        return;
      }

      if (action === 'open_note' || targetId.startsWith('note:')) {
        const target = event.path ?? event.filename ?? targetId.slice('note:'.length);
        openNote(target);
        renderSurface();
        return;
      }

      if (action === 'edit') {
        if (event.filename) {
          const clean = sanitizeNoteFilename(event.filename);
          state.filename = clean;
          state.currentPath = `${NOTES_DIR}/${clean}`;
        }
        if (event.content !== undefined || event.value !== undefined) {
          state.content = String(event.content ?? event.value ?? '');
        }
        state.dirty = true;
        renderSurface();
        return;
      }

      if (action === 'save' || action === 'save_note' || targetId === 'notes-save-btn') {
        saveCurrentNote(event.path ?? event.filename ?? null, event.content ?? event.value ?? null);
        renderSurface();
        return;
      }

      if (action === 'delete_note') {
        const target = resolveNotePath(event.path ?? event.filename ?? state.currentPath);
        os.vfs.unlink(target, vfsCtx());
        lastSyscall = 'vfs.unlink';
        if (state.currentPath === target) {
          state.filename = 'untitled.txt';
          state.currentPath = `${NOTES_DIR}/untitled.txt`;
          state.content = '';
          state.dirty = false;
        }
        refreshNotesList();
        state.errorMessage = null;
        state.statusMessage = `Deleted ${target}`;
        renderSurface();
        return;
      }

      if (action === 'copy' || targetId === 'notes-copy-btn') {
        const textToCopy = event.text !== undefined ? String(event.text) : state.content;
        os.clipboard.set({ text: textToCopy, sourceAppId: NOTES_APP_DESCRIPTOR.appId });
        lastSyscall = 'clipboard.set';
        state.errorMessage = null;
        state.statusMessage = `Copied ${textToCopy.length} chars to Shared Clipboard`;
        renderSurface();
        return;
      }

      if (action === 'paste' || targetId === 'notes-paste-btn') {
        const clipText = os.clipboard.get('text/plain');
        lastSyscall = 'clipboard.get';
        if (typeof clipText === 'string' && clipText.length > 0) {
          state.content = event.replace ? clipText : `${state.content}${clipText}`;
          state.dirty = true;
          state.errorMessage = null;
          state.statusMessage = `Pasted ${clipText.length} chars from Shared Clipboard`;
        } else {
          state.statusMessage = 'Shared Clipboard is empty';
        }
        renderSurface();
        return;
      }

      if (action === 'share' || targetId === 'notes-share-btn') {
        triggerShare(event.preferredAppId ?? null);
        return;
      }

      if (action === 'refresh') {
        refreshNotesList();
        renderSurface();
      }
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
      renderSurface();
    }
  };

  refreshNotesList();
  if (launchOpts.intent) {
    applyIncomingIntent(launchOpts.intent);
  } else if (launchOpts.path) {
    try {
      openNote(launchOpts.path);
    } catch (err) {
      state.errorMessage = err?.message ?? String(err);
    }
  }

  const win = os.compositor.createWindow(pcb.pid, {
    appId: NOTES_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `OmniNotes — ${state.filename}${state.dirty ? ' *' : ''}`,
    icon: NOTES_APP_DESCRIPTOR.icon,
    width: 740,
    height: 520,
    chromeStyle: 'unified',
    menuBar: NOTES_MENU_BAR,
    uiTree: buildUiTree(),
  });
  windowId = win.windowId;

  if (os.eventBus && typeof os.eventBus.on === 'function') {
    vfsUnsub = os.eventBus.on('vfs:changed', (ev) => {
      if (disposed) return;
      if (!ev?.path || String(ev.path).startsWith(NOTES_DIR)) {
        refreshNotesList();
        surfaceDirty = true;
      }
    });
  }

  return {
    windowId,
    flushPending: () => pendingAsync,
    step(budget = 100) {
      void budget;
      if (surfaceDirty && !disposed) {
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
        appId: NOTES_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ff90000,
        registers: {
          r0: state.notes.length,
          r1: state.content.length,
          r2: state.dirty ? 1 : 0,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ff90000,
        windowId,
        stateSummary: {
          currentPath: state.currentPath,
          filename: state.filename,
          contentLength: state.content.length,
          dirty: state.dirty,
          noteCount: state.notes.length,
          receivedIntentsCount: state.receivedIntents.length,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
