/**
 * OmniOS Built-in System App: Activity / Task Monitor (`com.omnios.monitor`, F-069)
 * Live PID table, Process Tree, real signal dispatch (SIGTERM/SIGKILL/SIGSTOP/SIGCONT catching EPERM on PID 0/1),
 * VMM page/heap telemetry, Service health & restart, and live kernel `dmesg` viewer + Canvas2D metrics bars.
 */

export const MONITOR_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.monitor',
  aliases: Object.freeze(['monitor', 'activity-monitor', 'task-monitor']),
  name: 'Activity Monitor',
  title: 'Activity & Task Monitor',
  platform: 'system',
  category: 'System',
  icon: 'activity',
  description: 'Live process manager, process tree, VMM telemetry, daemon health & dmesg viewer',
});

export const MONITOR_TABS = Object.freeze(['processes', 'tree', 'memory', 'services', 'dmesg']);

const MONITOR_MENU_BAR = Object.freeze([
  {
    id: 'monitor',
    label: 'Activity Monitor',
    items: [
      { id: 'monitor.refresh', label: 'Refresh Now' },
      { id: 'monitor.toggle_terminated', label: 'Toggle Terminated PIDs' },
      { id: 'monitor.close', label: 'Close Window' },
    ],
  },
  {
    id: 'tabs',
    label: 'View',
    items: [
      { id: 'tab.processes', label: 'Processes' },
      { id: 'tab.tree', label: 'Process Tree' },
      { id: 'tab.memory', label: 'Virtual Memory (VMM)' },
      { id: 'tab.services', label: 'System Services' },
      { id: 'tab.dmesg', label: 'Kernel dmesg' },
    ],
  },
]);

function parseStrictPid(raw) {
  if (typeof raw === 'number') {
    return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) return null;
    const n = Number(trimmed);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  }
  return null;
}

export function createMonitorExecutionContext(os, pcb, launchOpts = {}) {
  const initialTab = MONITOR_TABS.includes(launchOpts.tab) ? launchOpts.tab : 'processes';

  const state = {
    activeTab: initialTab,
    includeTerminated: false,
    selectedPid: null,
    dmesgLimit: 80,
    lastActionMessage: 'Monitoring live kernel state',
    lastError: null,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x3000;
  let lastSyscall = 'process.list';
  let windowId = null;
  let pendingAsync = Promise.resolve();
  const unsubs = [];

  const collectSnapshot = () => {
    const processes = os.processManager.list({ includeTerminated: state.includeTerminated });
    const tree = os.processManager.getTree({ includeTerminated: state.includeTerminated });
    const mem = os.processManager.getAggregateMemoryStats();
    const services = os.serviceManager.getStatus();
    const dmesg = os.kernel.dmesg({ limit: state.dmesgLimit });
    const schedulerStats = os.scheduler.getStats();

    let selectedProcessDetail = null;
    if (state.selectedPid !== null) {
      const targetPcb = os.processManager.get(state.selectedPid);
      if (targetPcb) {
        selectedProcessDetail = {
          ...os.processManager.toSummary(targetPcb),
          addressSpace: targetPcb.addressSpace?.getStats?.() ?? null,
          threads: os.processManager.listThreads(targetPcb.pid),
          fds: os.processManager.listFds(targetPcb.pid),
        };
      }
    }

    return { processes, tree, mem, services, dmesg, schedulerStats, selectedProcessDetail };
  };

  const buildDrawOps = (snap) => {
    const ops = [
      { op: 'fillRect', x: 0, y: 0, w: 400, h: 90, color: '#0f172a' },
      { op: 'drawText', x: 12, y: 20, text: `Active PIDs: ${snap.processes.length} | Mapped Pages: ${snap.mem.totalMappedPages}`, color: '#e2e8f0', font: '12px monospace' },
    ];
    const topProcs = snap.processes.slice(0, 6);
    const maxBytes = Math.max(4096, ...topProcs.map((p) => p.memory?.usedBytes ?? 0));
    for (let i = 0; i < topProcs.length; i += 1) {
      const p = topProcs[i];
      const used = p.memory?.usedBytes ?? 0;
      const barW = Math.max(8, Math.round((used / maxBytes) * 180));
      const y = 30 + i * 9;
      ops.push({ op: 'fillRect', x: 12, y, w: barW, h: 6, color: p.state === 'RUNNING' ? '#22c55e' : '#38bdf8' });
    }
    return ops;
  };

  const buildUiTree = (snap) => ({
    id: 'monitor-root',
    type: 'container',
    role: 'activity-monitor',
    props: {
      appId: MONITOR_APP_DESCRIPTOR.appId,
      activeTab: state.activeTab,
      includeTerminated: state.includeTerminated,
      selectedPid: state.selectedPid,
      processCount: snap.processes.length,
      serviceCount: snap.services.length,
      totalMappedPages: snap.mem.totalMappedPages,
      totalUsedBytes: snap.mem.totalUsedBytes,
      schedulerTicks: snap.schedulerStats.totalTicks,
      lastActionMessage: state.lastActionMessage,
      lastError: state.lastError,
    },
    children: [
      {
        id: 'monitor-tabs',
        type: 'toolbar',
        props: { activeTab: state.activeTab },
        children: [
          ...MONITOR_TABS.map((tab) => ({
            id: `tab-${tab}`,
            type: 'button',
            props: { label: tab.toUpperCase(), action: 'set_tab', tab, active: state.activeTab === tab },
          })),
          { id: 'monitor-refresh', type: 'button', props: { label: 'Refresh', action: 'refresh' } },
        ],
      },
      {
        id: 'monitor-content',
        type: 'panel',
        props: {
          tab: state.activeTab,
          processes: snap.processes,
          tree: snap.tree,
          memory: snap.mem,
          services: snap.services,
          dmesg: snap.dmesg,
          selectedProcessDetail: snap.selectedProcessDetail,
        },
        children:
          state.activeTab === 'processes'
            ? snap.processes.map((p) => ({
                id: `proc-${p.pid}`,
                type: 'row',
                props: {
                  pid: p.pid,
                  ppid: p.ppid,
                  name: p.name,
                  appId: p.appId,
                  platform: p.platform,
                  arch: p.arch,
                  state: p.state,
                  uid: p.uid,
                  usedBytes: p.memory?.usedBytes ?? 0,
                  mappedPages: p.memory?.mappedPages ?? 0,
                },
              }))
            : state.activeTab === 'services'
              ? snap.services.map((svc) => ({
                  id: `svc-${svc.name}`,
                  type: 'row',
                  props: {
                    name: svc.name,
                    state: svc.state,
                    essential: svc.essential,
                    restarts: svc.restarts,
                    totalRestarts: svc.totalRestarts,
                    healthy: svc.lastHealthOk ?? (svc.state === 'RUNNING'),
                    lastHealthOk: svc.lastHealthOk,
                    deps: svc.deps,
                  },
                }))
              : state.activeTab === 'dmesg'
                ? snap.dmesg.map((entry) => ({
                    id: `dmesg-${entry.seq}`,
                    type: 'text',
                    props: {
                      seq: entry.seq,
                      level: entry.level,
                      subsystem: entry.subsystem,
                      text: `[${entry.uptimeMs}ms] [${entry.level.toUpperCase()}] ${entry.subsystem}: ${entry.message}`,
                    },
                  }))
                : [],
      },
      {
        id: 'monitor-status',
        type: 'statusbar',
        props: {
          text: state.lastError ? `Error: ${state.lastError}` : state.lastActionMessage,
          error: state.lastError,
        },
      },
    ],
  });

  const renderSurface = () => {
    if (disposed || !windowId || !os.compositor) return;
    if (!os.compositor.getWindow(windowId)) return;
    const snap = collectSnapshot();
    try {
      os.compositor.updateSurface(windowId, {
        title: `Activity Monitor — ${snap.processes.length} PIDs (${state.activeTab})`,
        menuBar: MONITOR_MENU_BAR,
        uiTree: buildUiTree(snap),
        drawOps: buildDrawOps(snap),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'monitor-app', `Failed to update Activity Monitor surface: ${err.message}`);
    }
  };

  const dispose = (reason = 'disposed') => {
    if (disposed) return;
    disposed = true;
    exited = true;
    while (unsubs.length > 0) {
      const fn = unsubs.pop();
      if (typeof fn === 'function') fn();
    }
    if (windowId && os.compositor?.getWindow(windowId)) {
      try {
        os.compositor.closeWindow(windowId, { notifyProcess: false, reason });
      } catch (err) {
        os.kernel?.log('debug', 'monitor-app', `Window already closed on dispose: ${err.message}`);
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
        if (aid === 'monitor.refresh') {
          state.lastError = null;
          state.lastActionMessage = 'Refreshed';
          renderSurface();
        } else if (aid === 'monitor.toggle_terminated') {
          state.includeTerminated = !state.includeTerminated;
          renderSurface();
        } else if (aid === 'monitor.close') {
          lastSyscall = 'menu_close';
          dispose('menu_close');
        } else if (aid.startsWith('tab.')) {
          const tab = aid.slice('tab.'.length);
          if (MONITOR_TABS.includes(tab)) {
            state.activeTab = tab;
            renderSurface();
          }
        }
        return;
      }

      const action = event.action ?? '';
      const targetId = event.targetId ?? '';

      if (action === 'set_tab' || targetId.startsWith('tab-')) {
        const tab = event.tab ?? targetId.slice('tab-'.length);
        if (MONITOR_TABS.includes(tab)) {
          state.activeTab = tab;
          state.lastError = null;
          state.lastActionMessage = `Viewing ${tab}`;
          lastSyscall = `monitor.tab:${tab}`;
          renderSurface();
        }
        return;
      }

      if (action === 'refresh' || targetId === 'monitor-refresh') {
        state.lastError = null;
        state.lastActionMessage = 'Refreshed live metrics';
        lastSyscall = 'process.list';
        renderSurface();
        return;
      }

      if (action === 'toggle_terminated') {
        state.includeTerminated = !state.includeTerminated;
        renderSurface();
        return;
      }

      if (action === 'select_pid' || targetId.startsWith('proc-')) {
        const rawPid =
          event.targetPid ??
          event.data?.pid ??
          event.payload?.pid ??
          (targetId.startsWith('proc-') ? targetId.slice('proc-'.length) : undefined) ??
          event.value ??
          (event.windowId === undefined ? event.pid : undefined);
        const pid = parseStrictPid(rawPid);
        if (pid !== null) {
          state.selectedPid = pid;
          state.lastError = null;
          state.lastActionMessage = `Selected PID ${pid}`;
          renderSurface();
        } else {
          state.lastError = `Invalid targetPid: ${String(rawPid)}`;
          renderSurface();
        }
        return;
      }

      if (action === 'signal' || action === 'kill') {
        const rawPid =
          event.targetPid ??
          event.data?.pid ??
          event.payload?.pid ??
          (targetId.startsWith('proc-') ? targetId.slice('proc-'.length) : undefined) ??
          event.value ??
          state.selectedPid ??
          (event.windowId === undefined ? event.pid : undefined);
        const pid = parseStrictPid(rawPid);
        const signal = event.signal ?? 'SIGTERM';
        if (pid === null) {
          state.lastError = 'Valid targetPid is required for signal dispatch';
          renderSurface();
          return;
        }
        lastSyscall = `process.kill:${signal}`;
        const res = os.processManager.kill(pid, signal);
        state.lastError = null;
        state.lastActionMessage = `Sent ${res.signal} to PID ${res.pid} (state=${res.state})`;
        renderSurface();
        return;
      }

      if (action === 'restart_service') {
        const name = String(event.name ?? event.service ?? '');
        if (!name) {
          state.lastError = 'Service name is required';
          renderSurface();
          return;
        }
        lastSyscall = `service.restart:${name}`;
        state.lastError = null;
        state.lastActionMessage = `Restarting service ${name}...`;
        renderSurface();

        pendingAsync = Promise.resolve(os.serviceManager.restart(name))
          .then((res) => {
            state.lastActionMessage = `Service ${name} restarted (state=${res?.state ?? 'RUNNING'})`;
            if (!disposed) renderSurface();
          })
          .catch((err) => {
            state.lastError = err?.message ?? String(err);
            if (!disposed) renderSurface();
          });
      }
    } catch (err) {
      state.lastError = `[${err?.code ?? 'ERROR'}] ${err?.message ?? String(err)}`;
      renderSurface();
    }
  };

  const initialSnap = collectSnapshot();
  const win = os.compositor.createWindow(pcb.pid, {
    appId: MONITOR_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: `Activity Monitor — ${initialSnap.processes.length} PIDs (${state.activeTab})`,
    icon: MONITOR_APP_DESCRIPTOR.icon,
    width: 840,
    height: 560,
    chromeStyle: 'unified',
    menuBar: MONITOR_MENU_BAR,
    uiTree: buildUiTree(initialSnap),
    drawOps: buildDrawOps(initialSnap),
  });
  windowId = win.windowId;

  if (os.eventBus && typeof os.eventBus.on === 'function') {
    for (const evName of [
      'process:created',
      'process:state_changed',
      'process:exited',
      'process:reaped',
      'service:started',
      'service:stopped',
      'service:restarted',
      'service:failed',
      'service:unhealthy',
    ]) {
      unsubs.push(
        os.eventBus.on(evName, () => {
          if (!disposed) dirty = true;
        })
      );
    }
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
      const snap = collectSnapshot();
      return {
        arch: 'native',
        appId: MONITOR_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ffd0000,
        registers: {
          r0: snap.processes.length,
          r1: snap.services.length,
          r2: snap.mem.totalMappedPages,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ffd0000,
        windowId,
        stateSummary: {
          activeTab: state.activeTab,
          processCount: snap.processes.length,
          serviceCount: snap.services.length,
          lastError: state.lastError,
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
