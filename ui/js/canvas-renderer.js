// OmniOS M6 2D Canvas DrawOps Renderer & Pointer Interaction Module
// Supports Universal WASM, Win32 GDI32, Activity Monitor telemetry, iOS UIKit, and macOS AppKit drawOps.

import { sanitizeCssColor } from './ws-client.js';

function num(val, fallback = 0) {
  const n = Number(val);
  return Number.isFinite(n) ? n : fallback;
}

function safeCanvasColor(raw, fallback = null, isAndroid = false) {
  if (!raw || typeof raw !== 'string') return fallback;
  const trimmed = raw.trim();
  if (trimmed.toLowerCase() === 'transparent') return 'transparent';
  return sanitizeCssColor(trimmed, { isAndroid }) ?? fallback;
}

function drawRoundedRectPath(ctx, x, y, w, h, radius) {
  const r = Math.min(Math.max(0, radius), Math.abs(w) / 2, Math.abs(h) / 2);
  ctx.beginPath();
  if (r <= 0) {
    ctx.rect(x, y, w, h);
    return;
  }
  if (typeof ctx.roundRect === 'function') {
    ctx.roundRect(x, y, w, h, r);
    return;
  }
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

export function inferCanvasDimensions(drawOps, options = {}) {
  const explicitW = num(options.width, 0);
  const explicitH = num(options.height, 0);
  if (explicitW > 0 && explicitH > 0) {
    return {
      width: Math.max(1, Math.min(4096, Math.round(explicitW))),
      height: Math.max(1, Math.min(4096, Math.round(explicitH))),
    };
  }

  const ops = Array.isArray(drawOps) ? drawOps : [];
  let maxX = 0;
  let maxY = 0;
  let bgRectW = 0;
  let bgRectH = 0;

  for (let i = 0; i < ops.length; i += 1) {
    const item = ops[i];
    if (!item || typeof item !== 'object') continue;
    const op = item.op ?? item.type;
    if (op === 'rect' || op === 'fillRect' || op === 'strokeRect') {
      const x = num(item.x, 0);
      const y = num(item.y, 0);
      const w = num(item.width ?? item.w, 0);
      const h = num(item.height ?? item.h, 0);
      if (i === 0 && x === 0 && y === 0 && w >= 100 && h >= 40) {
        bgRectW = w;
        bgRectH = h;
      }
      if (x + w > maxX) maxX = x + w;
      if (y + h > maxY) maxY = y + h;
    } else if (op === 'circle') {
      const cx = num(item.cx ?? item.x, 0);
      const cy = num(item.cy ?? item.y, 0);
      const r = Math.max(0, num(item.r ?? item.radius, 0));
      if (cx + r > maxX) maxX = cx + r;
      if (cy + r > maxY) maxY = cy + r;
    } else if (op === 'ellipse') {
      const cx = num(item.cx ?? item.x, 0);
      const cy = num(item.cy ?? item.y, 0);
      const rx = Math.max(0, num(item.rx, 0));
      const ry = Math.max(0, num(item.ry, 0));
      if (cx + rx > maxX) maxX = cx + rx;
      if (cy + ry > maxY) maxY = cy + ry;
    } else if (op === 'line') {
      const x1 = num(item.x1, 0);
      const y1 = num(item.y1, 0);
      const x2 = num(item.x2, 0);
      const y2 = num(item.y2, 0);
      const lx = Math.max(x1, x2);
      const ly = Math.max(y1, y2);
      if (lx > maxX) maxX = lx;
      if (ly > maxY) maxY = ly;
    } else if (op === 'text' || op === 'drawText' || op === 'fillText') {
      const x = num(item.x, 0);
      const y = num(item.y, 0);
      const textLen = String(item.text ?? '').length;
      const estW = x + Math.min(textLen * 8, 600);
      const estH = y + 18;
      if (estW > maxX) maxX = estW;
      if (estH > maxY) maxY = estH;
    }
  }

  const minW = num(options.minWidth, 320);
  const minH = bgRectH >= 40 ? bgRectH : num(options.minHeight, 120);
  const rawW = bgRectW >= 100 ? Math.max(bgRectW, maxX) : Math.max(minW, maxX);
  const rawH = bgRectH >= 40 ? Math.max(bgRectH, maxY) : Math.max(minH, maxY);

  return {
    width: Math.max(1, Math.min(2048, Math.ceil(rawW))),
    height: Math.max(1, Math.min(2048, Math.ceil(rawH))),
  };
}

export function renderDrawOps(canvas, drawOps, options = {}) {
  if (!canvas || typeof canvas.getContext !== 'function') {
    return { renderedOps: 0, width: 0, height: 0 };
  }

  const ops = Array.isArray(drawOps) ? drawOps : [];
  const { width, height } = inferCanvasDimensions(ops, options);

  // Resize logical backing store only when dimensions change
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;

  const ctx = canvas.getContext('2d');
  if (!ctx) return { renderedOps: 0, width, height };

  const isAndroid = Boolean(options.isAndroid);

  ctx.save();
  ctx.clearRect(0, 0, width, height);

  if (options.background) {
    const bg = safeCanvasColor(options.background, null, isAndroid);
    if (bg && bg !== 'transparent') {
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, width, height);
    }
  }

  let renderedOps = 0;

  for (let i = 0; i < ops.length; i += 1) {
    const item = ops[i];
    if (!item || typeof item !== 'object') continue;
    const op = item.op ?? item.type;
    if (typeof op !== 'string') continue;

    if (op === 'clear') {
      ctx.clearRect(0, 0, width, height);
      const color = safeCanvasColor(item.color ?? item.fill, null, isAndroid);
      if (color && color !== 'transparent') {
        ctx.fillStyle = color;
        ctx.fillRect(0, 0, width, height);
      }
      renderedOps += 1;
      continue;
    }

    if (op === 'rect' || op === 'fillRect' || op === 'strokeRect') {
      const x = num(item.x, 0);
      const y = num(item.y, 0);
      const w = num(item.width ?? item.w, 0);
      const h = num(item.height ?? item.h, 0);
      const radius = Math.max(0, num(item.radius ?? item.r, 0));
      const fillRaw = item.fill ?? (op !== 'strokeRect' ? item.color : null);
      const strokeRaw = item.stroke ?? (op === 'strokeRect' ? item.color : null);
      const fill = safeCanvasColor(fillRaw, null, isAndroid);
      const stroke = safeCanvasColor(strokeRaw, null, isAndroid);
      const lineWidth = Math.max(0, num(item.lineWidth ?? item.strokeWidth, 1));

      if (radius > 0) {
        drawRoundedRectPath(ctx, x, y, w, h, radius);
        if (fill && fill !== 'transparent') {
          ctx.fillStyle = fill;
          ctx.fill();
        }
        if (stroke && stroke !== 'transparent' && lineWidth > 0) {
          ctx.strokeStyle = stroke;
          ctx.lineWidth = lineWidth;
          ctx.stroke();
        }
      } else {
        if (fill && fill !== 'transparent') {
          ctx.fillStyle = fill;
          ctx.fillRect(x, y, w, h);
        }
        if (stroke && stroke !== 'transparent' && lineWidth > 0) {
          ctx.strokeStyle = stroke;
          ctx.lineWidth = lineWidth;
          ctx.strokeRect(x, y, w, h);
        }
      }
      renderedOps += 1;
      continue;
    }

    if (op === 'circle') {
      const cx = num(item.cx ?? item.x, 0);
      const cy = num(item.cy ?? item.y, 0);
      const r = Math.max(0, num(item.r ?? item.radius, 0));
      const fill = safeCanvasColor(item.fill ?? item.color, null, isAndroid);
      const stroke = safeCanvasColor(item.stroke, null, isAndroid);
      const lineWidth = Math.max(0, num(item.lineWidth ?? item.strokeWidth, 1));

      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      if (fill && fill !== 'transparent') {
        ctx.fillStyle = fill;
        ctx.fill();
      }
      if (stroke && stroke !== 'transparent' && lineWidth > 0) {
        ctx.strokeStyle = stroke;
        ctx.lineWidth = lineWidth;
        ctx.stroke();
      }
      renderedOps += 1;
      continue;
    }

    if (op === 'ellipse') {
      const cx = num(item.cx ?? item.x, 0);
      const cy = num(item.cy ?? item.y, 0);
      const rx = Math.max(0, num(item.rx, 0));
      const ry = Math.max(0, num(item.ry, 0));
      const fill = safeCanvasColor(item.fill ?? item.color, null, isAndroid);
      const stroke = safeCanvasColor(item.stroke, null, isAndroid);
      const lineWidth = Math.max(0, num(item.lineWidth ?? item.strokeWidth, 1));

      ctx.beginPath();
      ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
      if (fill && fill !== 'transparent') {
        ctx.fillStyle = fill;
        ctx.fill();
      }
      if (stroke && stroke !== 'transparent' && lineWidth > 0) {
        ctx.strokeStyle = stroke;
        ctx.lineWidth = lineWidth;
        ctx.stroke();
      }
      renderedOps += 1;
      continue;
    }

    if (op === 'line') {
      const x1 = num(item.x1, 0);
      const y1 = num(item.y1, 0);
      const x2 = num(item.x2, 0);
      const y2 = num(item.y2, 0);
      const stroke = safeCanvasColor(item.stroke ?? item.color, '#94a3b8', isAndroid);
      const lineWidth = Math.max(0.5, num(item.lineWidth ?? item.strokeWidth, 1));
      if (stroke && stroke !== 'transparent') {
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = stroke;
        ctx.lineWidth = lineWidth;
        ctx.stroke();
      }
      renderedOps += 1;
      continue;
    }

    if (op === 'text' || op === 'drawText' || op === 'fillText') {
      const text = String(item.text ?? '');
      const x = num(item.x, 0);
      const y = num(item.y, 0);
      const font =
        typeof item.font === 'string' && item.font.trim()
          ? item.font.trim()
          : `${Math.max(6, num(item.fontSize, 14))}px sans-serif`;
      const fill = safeCanvasColor(item.color ?? item.fill, '#f8fafc', isAndroid);
      const baseline =
        op === 'text' && typeof item.font === 'string' && item.fontSize === undefined
          ? 'top'
          : 'alphabetic';
      ctx.font = font;
      ctx.textBaseline = baseline;
      ctx.fillStyle = fill && fill !== 'transparent' ? fill : '#f8fafc';
      ctx.fillText(text, x, y);
      renderedOps += 1;
    }
  }

  ctx.restore();
  return { renderedOps, width, height };
}

const CANVAS_INTERACTION_STATE = new WeakMap();

export function attachCanvasInteraction(canvas, { onCanvasClick, onCanvasDrag } = {}) {
  if (!canvas) return () => {};

  const existing = CANVAS_INTERACTION_STATE.get(canvas);
  if (existing) {
    existing.onCanvasClick = onCanvasClick;
    existing.onCanvasDrag = onCanvasDrag;
    return existing.detach;
  }

  const state = {
    onCanvasClick,
    onCanvasDrag,
    isDown: false,
    didDrag: false,
    startX: 0,
    startY: 0,
    lastDragTs: 0,
    detach: null,
  };

  function getLogicalPoint(ev) {
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return { x: 0, y: 0 };
    const x = ((ev.clientX - rect.left) / rect.width) * canvas.width;
    const y = ((ev.clientY - rect.top) / rect.height) * canvas.height;
    return {
      x: Math.max(0, Math.min(canvas.width, Math.round(x))),
      y: Math.max(0, Math.min(canvas.height, Math.round(y))),
    };
  }

  function onPointerDown(ev) {
    if (ev.button !== 0) return;
    state.isDown = true;
    state.didDrag = false;
    state.startX = ev.clientX;
    state.startY = ev.clientY;
    state.lastDragTs = 0;
  }

  function onPointerMove(ev) {
    // NEVER emit passive hover pointer_move — only active drag > 6px
    if (!state.isDown) return;
    const dist = Math.hypot(ev.clientX - state.startX, ev.clientY - state.startY);
    if (dist <= 6) return;
    state.didDrag = true;
    if (typeof state.onCanvasDrag !== 'function') return;
    const now = performance.now();
    if (now - state.lastDragTs < 45) return;
    state.lastDragTs = now;
    const pt = getLogicalPoint(ev);
    state.onCanvasDrag({ type: 'pointer_move', x: pt.x, y: pt.y });
  }

  function onPointerUp() {
    state.isDown = false;
  }

  function onClick(ev) {
    if (state.didDrag) {
      state.didDrag = false;
      return;
    }
    if (typeof state.onCanvasClick !== 'function') return;
    const pt = getLogicalPoint(ev);
    state.onCanvasClick({ type: 'click', x: pt.x, y: pt.y });
  }

  canvas.addEventListener('pointerdown', onPointerDown);
  canvas.addEventListener('pointermove', onPointerMove);
  canvas.addEventListener('pointerup', onPointerUp);
  canvas.addEventListener('pointercancel', onPointerUp);
  canvas.addEventListener('click', onClick);

  state.detach = () => {
    canvas.removeEventListener('pointerdown', onPointerDown);
    canvas.removeEventListener('pointermove', onPointerMove);
    canvas.removeEventListener('pointerup', onPointerUp);
    canvas.removeEventListener('pointercancel', onPointerUp);
    canvas.removeEventListener('click', onClick);
    CANVAS_INTERACTION_STATE.delete(canvas);
  };

  CANVAS_INTERACTION_STATE.set(canvas, state);
  return state.detach;
}
