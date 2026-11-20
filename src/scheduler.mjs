/**
 * Zero-dependency 5-field cron expression parser & background scheduler
 * for 24/7 Hostinger execution.
 *
 * Field order: minute (0-59) | hour (0-23) | dayOfMonth (1-31) | month (1-12) | dayOfWeek (0-6, 0=Sun)
 */

export function matchesCronField(field, value) {
  const parts = String(field).trim().split(',');
  for (const part of parts) {
    if (part === '*') return true;
    if (part.startsWith('*/')) {
      const step = Number(part.slice(2));
      if (step > 0 && value % step === 0) return true;
      continue;
    }
    if (part.includes('-')) {
      const [rangePart, stepPart] = part.split('/');
      const [start, end] = rangePart.split('-').map(Number);
      const step = stepPart ? Number(stepPart) : 1;
      if (value >= start && value <= end && (value - start) % step === 0) return true;
      continue;
    }
    if (Number(part) === value) return true;
  }
  return false;
}

export function matchesCron(expression, date = new Date()) {
  const fields = String(expression || '').trim().split(/\s+/);
  if (fields.length !== 5) return false;
  const [min, hour, dom, month, dow] = fields;
  return (
    matchesCronField(min, date.getUTCMinutes()) &&
    matchesCronField(hour, date.getUTCHours()) &&
    matchesCronField(dom, date.getUTCDate()) &&
    matchesCronField(month, date.getUTCMonth() + 1) &&
    matchesCronField(dow, date.getUTCDay())
  );
}

export function getNextRunTime(expression, fromDate = new Date()) {
  const fields = String(expression || '').trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const probe = new Date(fromDate.getTime());
  probe.setUTCSeconds(0, 0);
  probe.setUTCMinutes(probe.getUTCMinutes() + 1);

  // Look ahead up to 14 days (20,160 minutes)
  for (let i = 0; i < 20160; i++) {
    if (matchesCron(expression, probe)) {
      return probe.toISOString();
    }
    probe.setUTCMinutes(probe.getUTCMinutes() + 1);
  }
  return null;
}

export class CronScheduler {
  constructor({ engine, memory }) {
    this.engine = engine;
    this.memory = memory;
    this._timer = null;
    this._lastMinuteKey = '';
  }

  start() {
    if (this._timer) return;
    this._timer = setInterval(() => {
      this.tick(new Date()).catch((err) => {
        this.memory.logActivity('scheduler', `Tick error: ${err.message}`, { level: 'error' });
      });
    }, 15_000);
    if (typeof this._timer.unref === 'function') {
      this._timer.unref();
    }
  }

  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  getScheduledWorkflows() {
    const workflows = this.memory.listWorkflows();
    const list = [];
    for (const wf of workflows) {
      const cronNode = (wf.definition.nodes || []).find((n) => n.type === 'trigger.cron');
      if (!cronNode) continue;
      const schedule = cronNode.config?.schedule || '';
      list.push({
        workflowId: wf.id,
        name: wf.name,
        enabled: wf.enabled,
        runner: wf.runner,
        schedule,
        nextRunUtc: wf.enabled ? getNextRunTime(schedule) : null,
      });
    }
    return list;
  }

  async tick(now = new Date()) {
    const minuteKey = now.toISOString().slice(0, 16);
    if (minuteKey === this._lastMinuteKey) return [];
    this._lastMinuteKey = minuteKey;

    const triggered = [];
    for (const item of this.getScheduledWorkflows()) {
      if (!item.enabled) continue;
      if (item.runner === 'github') continue; // GitHub-only workflows run via GitHub Actions
      if (matchesCron(item.schedule, now)) {
        triggered.push(item.workflowId);
        await this.engine.runWorkflow(item.workflowId, {
          triggerType: 'cron',
          payload: { scheduledAt: now.toISOString(), cron: item.schedule },
        });
      }
    }
    return triggered;
  }
}
