/**
 * OmniOS Built-in System App: OmniTerm (`com.omnios.terminal`, F-067)
 * Real kernel-backed process + CompositorWindow wired live to its own ShellInterpreter instance.
 * Zero host filesystem access; strictly synchronous `IExecutionContext.step(budget)`.
 */

import { createShellInterpreter } from './shell-interpreter.mjs';

export const TERMINAL_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.terminal',
  aliases: Object.freeze(['terminal', 'omniterm']),
  name: 'OmniTerm',
  title: 'OmniTerm — Multi-Syntax Shell',
  platform: 'system',
  category: 'Utilities',
  icon: 'terminal',
  description: 'Unified POSIX, Windows, macOS, Android & ospm interactive terminal',
});

const MAX_SCROLLBACK_LINES = 400;

const TERMINAL_MENU_BAR = Object.freeze([
  {
    id: 'terminal',
    label: 'OmniTerm',
    items: [
      { id: 'terminal.clear', label: 'Clear Buffer' },
      { id: 'terminal.reset', label: 'Reset Shell' },
      { id: 'terminal.close', label: 'Close Window' },
    ],
  },
  {
    id: 'edit',
    label: 'Edit',
    items: [
      { id: 'edit.copy', label: 'Copy Last Output' },
      { id: 'edit.paste', label: 'Paste to Prompt' },
    ],
  },
  {
    id: 'shell',
    label: 'Shell',
    items: [
      { id: 'shell.help', label: 'Show Command Help' },
      { id: 'shell.ps', label: 'List Processes (ps)' },
      { id: 'shell.ls', label: 'List Directory (ls -la)' },
    ],
  },
]);

export function createTerminalExecutionContext(os, pcb, launchOpts = {}) {
  const shell = createShellInterpreter(os, {
    cwd: typeof launchOpts.cwd === 'string' && launchOpts.cwd.length > 0 ? launchOpts.cwd : '/home/user',
    env: launchOpts.env && typeof launchOpts.env === 'object' ? launchOpts.env : {},
  });

  const state = {
    lines: [
      { kind: 'banner', text: 'OmniOS Multi-Syntax Shell (POSIX | Windows | macOS | Android | ospm)' },
      { kind: 'info', text: 'Type "help" for available commands.' },
    ],
    draft: '',
    historyCursor: -1,
    lastExitCode: 0,
    lastOutput: '',
    runningCommand: null,
    commandCount: 0,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x1000;
  let lastSyscall = 'init';
  let windowId = null;
  let pendingExec = Promise.resolve();
  const eventQueue = [];

  const appendLine = (kind, text) => {
    const raw = String(text ?? '');
    const split = raw.length > 0 ? raw.replace(/\r\n/g, '\n').split('\n') : [''];
    for (let i = 0; i < split.length; i += 1) {
      if (i === split.length - 1 && split[i] === '' && split.length > 1) continue;
      state.lines.push({ kind, text: split[i] });
    }
    if (state.lines.length > MAX_SCROLLBACK_LINES) {
      state.lines.splice(0, state.lines.length - MAX_SCROLLBACK_LINES);
    }
  };

  const buildPrompt = () => `user@omnios:${shell.cwd}$`;

  const buildUiTree = () => ({
    id: 'omniterm-root',
    type: 'container',
    role: 'terminal',
    props: {
      appId: TERMINAL_APP_DESCRIPTOR.appId,
      cwd: shell.cwd,
      prompt: buildPrompt(),
      lastExitCode: state.lastExitCode,
      runningCommand: state.runningCommand,
      commandCount: state.commandCount,
    },
    children: [
      {
        id: 'term-header',
        type: 'toolbar',
        props: { cwd: shell.cwd, badge: 'POSIX / Win / macOS / Android / ospm' },
        children: [
          { id: 'term-cwd-label', type: 'text', props: { text: `CWD: ${shell.cwd}` } },
          { id: 'term-clear', type: 'button', props: { label: 'Clear', action: 'clear' } },
          { id: 'term-help-btn', type: 'button', props: { label: 'Help', action: 'exec', command: 'help' } },
        ],
      },
      {
        id: 'term-output',
        type: 'scrollview',
        props: {
          lineCount: state.lines.length,
          transcript: state.lines.map((l) => l.text).join('\n'),
        },
        children: state.lines.map((line, idx) => ({
          id: `term-line-${idx}`,
          type: 'text',
          props: { kind: line.kind, text: line.text },
        })),
      },
      {
        id: 'term-input-row',
        type: 'row',
        props: { prompt: buildPrompt() },
        children: [
          { id: 'term-prompt', type: 'text', props: { text: buildPrompt() } },
          {
            id: 'term-input',
            type: 'input',
            props: {
              value: state.draft,
              placeholder: 'Enter command (ls, dir, reg, defaults, pm, ospm, ...)',
              submitAction: 'exec',
            },
          },
          { id: 'term-run', type: 'button', props: { label: 'Run', action: 'run' } },
        ],
      },
    ],
  });

  const renderSurface = () => {
    if (disposed || !windowId || !os.compositor) return;
    if (!os.compositor.getWindow(windowId)) return;
    try {
      os.compositor.updateSurface(windowId, {
        title: `OmniTerm — ${shell.cwd}`,
        menuBar: TERMINAL_MENU_BAR,
        uiTree: buildUiTree(),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'terminal-app', `Failed to update OmniTerm surface: ${err.message}`);
    }
  };

  const executeCommand = (rawCommand) => {
    const cmd = String(rawCommand ?? '').trim();
    state.draft = '';
    state.historyCursor = -1;
    if (!cmd) {
      renderSurface();
      return;
    }

    appendLine('prompt', `${buildPrompt()} ${cmd}`);
    state.runningCommand = cmd;
    state.commandCount += 1;
    lastSyscall = `shell.exec:${cmd.split(/\s+/)[0]}`;
    pc += 4;
    instructionsExecuted += 12;
    renderSurface();

    pendingExec = pendingExec
      .then(async () => {
        const res = await shell.exec(cmd, { uid: pcb.uid, gid: pcb.gid });
        state.runningCommand = null;
        state.lastExitCode = res.exitCode;
        if (res.cleared) {
          state.lines = [];
        }
        if (res.stdout) {
          appendLine('stdout', res.stdout);
          state.lastOutput = res.stdout;
          try {
            os.processManager.writeStdout(pcb.pid, res.stdout);
          } catch (ioErr) {
            os.kernel?.log('debug', 'terminal-app', `writeStdout skipped: ${ioErr.message}`);
          }
        }
        if (res.stderr) {
          appendLine('stderr', res.stderr);
          try {
            os.processManager.writeStderr(pcb.pid, res.stderr);
          } catch (ioErr) {
            os.kernel?.log('debug', 'terminal-app', `writeStderr skipped: ${ioErr.message}`);
          }
        }
        instructionsExecuted += 24;
        if (!disposed) {
          renderSurface();
        }
      })
      .catch((err) => {
        state.runningCommand = null;
        state.lastExitCode = 1;
        appendLine('stderr', `Execution error: ${err?.message ?? String(err)}`);
        if (!disposed) {
          renderSurface();
        }
      });
  };

  const dispose = (reason = 'disposed') => {
    if (disposed) return;
    disposed = true;
    exited = true;
    if (windowId && os.compositor?.getWindow(windowId)) {
      try {
        os.compositor.closeWindow(windowId, { notifyProcess: false, reason });
      } catch (err) {
        os.kernel?.log('debug', 'terminal-app', `Window already closed on dispose: ${err.message}`);
      }
    }
  };

  const handleEventImmediate = (event) => {
    if (!event || typeof event !== 'object' || disposed) return;
    pc += 2;
    instructionsExecuted += 4;

    if (event.type === 'window_close' || event.type === 'terminate') {
      lastSyscall = 'window_close';
      dispose(event.type);
      return;
    }

    if (event.type === 'menu_action') {
      const actionId = event.actionId ?? event.itemId ?? event.id ?? '';
      lastSyscall = `menu:${actionId}`;
      if (actionId === 'terminal.clear') {
        state.lines = [];
        renderSurface();
      } else if (actionId === 'terminal.reset') {
        shell.cwd = '/home/user';
        shell.env.PWD = '/home/user';
        state.lines = [{ kind: 'banner', text: 'Shell reset to /home/user' }];
        renderSurface();
      } else if (actionId === 'terminal.close') {
        dispose('menu_close');
      } else if (actionId === 'edit.copy' && state.lastOutput) {
        os.clipboard?.set({ text: state.lastOutput, sourceAppId: TERMINAL_APP_DESCRIPTOR.appId });
        renderSurface();
      } else if (actionId === 'edit.paste') {
        const clipText = os.clipboard?.get('text/plain');
        if (typeof clipText === 'string' && clipText.length > 0) {
          state.draft += clipText;
          renderSurface();
        }
      } else if (actionId === 'shell.help') {
        executeCommand('help');
      } else if (actionId === 'shell.ps') {
        executeCommand('ps');
      } else if (actionId === 'shell.ls') {
        executeCommand('ls -la');
      }
      return;
    }

    if (event.type === 'intent') {
      const intentCmd = event.intent?.extras?.command ?? event.extras?.command;
      if (typeof intentCmd === 'string' && intentCmd.trim().length > 0) {
        executeCommand(intentCmd);
      }
      return;
    }

    if (event.type === 'input' || event.type === 'change') {
      if (event.value !== undefined) {
        state.draft = String(event.value);
        lastSyscall = 'ui.input';
        renderSurface();
      }
      return;
    }

    if (event.type === 'keydown') {
      const key = String(event.key ?? '');
      if (key === 'Enter') {
        const cmd = event.value !== undefined ? String(event.value) : state.draft;
        executeCommand(cmd);
        return;
      }
      if (key === 'ArrowUp') {
        const hist = shell.getHistory(200);
        if (hist.length > 0) {
          if (state.historyCursor === -1) state.historyCursor = hist.length - 1;
          else if (state.historyCursor > 0) state.historyCursor -= 1;
          state.draft = hist[state.historyCursor] ?? '';
          renderSurface();
        }
        return;
      }
      if (key === 'ArrowDown') {
        const hist = shell.getHistory(200);
        if (state.historyCursor !== -1) {
          if (state.historyCursor < hist.length - 1) {
            state.historyCursor += 1;
            state.draft = hist[state.historyCursor] ?? '';
          } else {
            state.historyCursor = -1;
            state.draft = '';
          }
          renderSurface();
        }
        return;
      }
      return;
    }

    if (event.type === 'submit') {
      const cmd = event.command ?? event.value ?? state.draft;
      executeCommand(cmd);
      return;
    }

    if (event.type === 'click' || event.type === 'action') {
      const act = event.action ?? '';
      const targetId = event.targetId ?? '';
      if (act === 'clear' || targetId === 'term-clear') {
        state.lines = [];
        lastSyscall = 'term.clear';
        renderSurface();
        return;
      }
      if (act === 'exec' || act === 'submit' || act === 'run' || targetId === 'term-run') {
        const cmd = event.command ?? event.value ?? state.draft;
        executeCommand(cmd);
        return;
      }
      if (targetId === 'term-help-btn') {
        executeCommand('help');
        return;
      }
      if (act === 'copy_output' && state.lastOutput) {
        os.clipboard?.set({ text: state.lastOutput, sourceAppId: TERMINAL_APP_DESCRIPTOR.appId });
        renderSurface();
        return;
      }
      if (act === 'paste') {
        const clipText = os.clipboard?.get('text/plain');
        if (typeof clipText === 'string' && clipText.length > 0) {
          state.draft += clipText;
          renderSurface();
        }
      }
    }
  };

  // Create real CompositorWindow immediately upon launch
  const win = os.compositor.createWindow(pcb.pid, {
    appId: TERMINAL_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `OmniTerm — ${shell.cwd}`,
    icon: TERMINAL_APP_DESCRIPTOR.icon,
    width: 760,
    height: 500,
    chromeStyle: 'unified',
    menuBar: TERMINAL_MENU_BAR,
    uiTree: buildUiTree(),
  });
  windowId = win.windowId;

  // Auto-run optional startup command
  const initialCmd = launchOpts.command ?? launchOpts.intent?.extras?.command;
  if (typeof initialCmd === 'string' && initialCmd.trim().length > 0) {
    executeCommand(initialCmd);
  }

  return {
    windowId,
    shell,
    flushPending: () => pendingExec,
    step(budget = 100) {
      const cap = Math.max(1, Number.isFinite(budget) ? Math.trunc(budget) : 100);
      let ran = 0;
      while (eventQueue.length > 0 && ran < cap) {
        const ev = eventQueue.shift();
        handleEventImmediate(ev);
        ran += 1;
      }
      if (dirty && !disposed) {
        renderSurface();
        ran += 1;
      }
      if (exited || disposed) {
        return { status: 'EXITED', exitCode: 0, instructionsExecuted: Math.max(1, ran) };
      }
      return { status: 'BLOCKED', waitReason: 'ui_event', instructionsExecuted: Math.max(1, ran) };
    },
    deliverEvent(event) {
      if (disposed) return;
      handleEventImmediate(event);
    },
    getDebugState() {
      return {
        arch: 'native',
        appId: TERMINAL_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7fff0000,
        registers: {
          r0: state.lastExitCode,
          r1: state.commandCount,
          r2: state.lines.length,
          r3: shell.history.length,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7fff0000,
        windowId,
        stateSummary: {
          cwd: shell.cwd,
          lineCount: state.lines.length,
          commandCount: state.commandCount,
          lastExitCode: state.lastExitCode,
          runningCommand: state.runningCommand,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
