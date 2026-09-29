// ── Chart primitives (inline SVG, no libs) ──────────────────────────────────
function svgLineChart(series, labels, opts = {}) {
  const w = opts.width || 900, h = opts.height || 220, pad = { l: 40, r: 16, t: 16, b: 28 };
  const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
  const n = labels.length;
  if (!n) return `<div class="text-outline text-sm italic">No data</div>`;
  const allValues = series.flatMap(s => s.values);
  const maxY = Math.max(1, ...allValues);
  const x = i => pad.l + (n === 1 ? iw / 2 : (i * iw) / (n - 1));
  const y = v => pad.t + ih - (v / maxY) * ih;
  const yTicks = 4;
  const gridLines = Array.from({ length: yTicks + 1 }, (_, i) => {
    const v = (maxY * i) / yTicks;
    const yy = y(v);
    return `<line x1="${pad.l}" x2="${pad.l+iw}" y1="${yy}" y2="${yy}" stroke="rgba(255,255,255,0.06)"/>
            <text x="${pad.l - 6}" y="${yy + 3}" text-anchor="end" font-size="10" fill="#a0a8b4" font-family="monospace">${Math.round(v)}</text>`;
  }).join('');
  // X labels — show at most ~8 evenly spaced
  const step = Math.max(1, Math.ceil(n / 8));
  const xLabels = labels.map((lbl, i) => {
    if (i % step !== 0 && i !== n - 1) return '';
    return `<text x="${x(i)}" y="${h - 8}" text-anchor="middle" font-size="9" fill="#a0a8b4" font-family="monospace">${escHtml(lbl.slice(5))}</text>`;
  }).join('');
  const lines = series.map(s => {
    const points = s.values.map((v, i) => `${x(i)},${y(v)}`).join(' ');
    const dots = s.values.map((v, i) => `<circle cx="${x(i)}" cy="${y(v)}" r="2.5" fill="${s.color}"/>`).join('');
    return `<polyline fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" points="${points}"/>${dots}`;
  }).join('');
  const legend = series.map(s => `<span class="inline-flex items-center gap-1.5 text-[11px] text-on-surface-variant mr-4"><span class="inline-block w-3 h-[3px]" style="background:${s.color}"></span>${escHtml(s.label)}</span>`).join('');
  return `<div>
    <div class="mb-2">${legend}</div>
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px">${gridLines}${lines}${xLabels}</svg>
  </div>`;
}

function svgBarChart(series, labels, opts = {}) {
  const w = opts.width || 900, h = opts.height || 220, pad = { l: 40, r: 16, t: 16, b: 28 };
  const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
  const n = labels.length;
  if (!n) return `<div class="text-outline text-sm italic">No data</div>`;
  const stacked = opts.stacked !== false;
  // Compute max
  let maxY = 1;
  for (let i = 0; i < n; i++) {
    if (stacked) {
      const sum = series.reduce((s, sr) => s + (sr.values[i] || 0), 0);
      if (sum > maxY) maxY = sum;
    } else {
      for (const sr of series) if ((sr.values[i] || 0) > maxY) maxY = sr.values[i];
    }
  }
  const x = i => pad.l + (i * iw) / n;
  const barW = Math.max(2, iw / n - 2);
  const y = v => pad.t + ih - (v / maxY) * ih;
  const yTicks = 4;
  const gridLines = Array.from({ length: yTicks + 1 }, (_, i) => {
    const v = (maxY * i) / yTicks;
    const yy = y(v);
    return `<line x1="${pad.l}" x2="${pad.l+iw}" y1="${yy}" y2="${yy}" stroke="rgba(255,255,255,0.06)"/>
            <text x="${pad.l - 6}" y="${yy + 3}" text-anchor="end" font-size="10" fill="#a0a8b4" font-family="monospace">${Math.round(v)}</text>`;
  }).join('');
  const step = Math.max(1, Math.ceil(n / 8));
  const xLabels = labels.map((lbl, i) => (i % step !== 0 && i !== n - 1) ? '' :
    `<text x="${x(i) + barW/2}" y="${h - 8}" text-anchor="middle" font-size="9" fill="#a0a8b4" font-family="monospace">${escHtml(lbl.slice(5))}</text>`).join('');
  let bars = '';
  for (let i = 0; i < n; i++) {
    if (stacked) {
      let cumulative = 0;
      for (const sr of series) {
        const v = sr.values[i] || 0;
        if (v === 0) continue;
        const bottom = y(cumulative);
        const top = y(cumulative + v);
        bars += `<rect x="${x(i) + 1}" y="${top}" width="${barW - 2}" height="${bottom - top}" fill="${sr.color}"/>`;
        cumulative += v;
      }
    } else {
      const barSlice = barW / series.length;
      series.forEach((sr, si) => {
        const v = sr.values[i] || 0;
        const top = y(v);
        bars += `<rect x="${x(i) + si * barSlice + 1}" y="${top}" width="${barSlice - 2}" height="${pad.t + ih - top}" fill="${sr.color}"/>`;
      });
    }
  }
  const legend = series.map(sr => `<span class="inline-flex items-center gap-1.5 text-[11px] text-on-surface-variant mr-4"><span class="inline-block w-3 h-3 rounded-sm" style="background:${sr.color}"></span>${escHtml(sr.label)}</span>`).join('');
  return `<div><div class="mb-2">${legend}</div>
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px">${gridLines}${bars}${xLabels}</svg>
  </div>`;
}

function svgDonut(segments) {
  const total = segments.reduce((s, g) => s + g.value, 0);
  if (total === 0) return `<div class="text-outline text-sm italic py-8 text-center">No data</div>`;
  const size = 180, cx = size / 2, cy = size / 2, r = 70, rInner = 48;
  let a0 = -Math.PI / 2;
  const arcs = segments.map(seg => {
    if (seg.value === 0) return '';
    const a1 = a0 + (seg.value / total) * 2 * Math.PI;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
    const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
    const xi0 = cx + rInner * Math.cos(a1), yi0 = cy + rInner * Math.sin(a1);
    const xi1 = cx + rInner * Math.cos(a0), yi1 = cy + rInner * Math.sin(a0);
    const d = `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} L ${xi0} ${yi0} A ${rInner} ${rInner} 0 ${large} 0 ${xi1} ${yi1} Z`;
    a0 = a1;
    return `<path d="${d}" fill="${seg.color}" opacity="0.92"/>`;
  }).join('');
  const legend = segments.map(seg => {
    const pct = total > 0 ? ((seg.value / total) * 100).toFixed(1) : '0.0';
    return `<div class="flex items-center justify-between gap-2 text-xs py-1">
      <div class="flex items-center gap-2 min-w-0">
        <span class="inline-block w-3 h-3 rounded-sm flex-shrink-0" style="background:${seg.color}"></span>
        <span class="truncate">${escHtml(seg.label)}</span>
      </div>
      <div class="mono-text text-on-surface-variant whitespace-nowrap">${seg.value.toLocaleString()} · ${pct}%</div>
    </div>`;
  }).join('');
  return `<div class="flex flex-col md:flex-row gap-6 items-center">
    <svg viewBox="0 0 ${size} ${size}" style="width:${size}px;height:${size}px;flex-shrink:0">${arcs}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="11" fill="#a0a8b4" font-family="monospace">Total</text>
      <text x="${cx}" y="${cy + 14}" text-anchor="middle" font-size="18" fill="#e6edf3" font-weight="700" font-family="monospace">${total.toLocaleString()}</text>
    </svg>
    <div class="flex-1 min-w-0 w-full">${legend}</div>
  </div>`;
}

function svgHBars(categories, barColor) {
  const color = barColor || AN_COLORS.app;
  if (!categories.length) return `<div class="text-outline text-sm italic py-4">No data</div>`;
  const max = Math.max(1, ...categories.map(c => c.count));
  return `<div class="space-y-2">${categories.map(c => {
    const pct = (c.count / max) * 100;
    return `<div>
      <div class="flex justify-between items-center text-[11px] mb-1">
        <span class="truncate pr-2">${escHtml(c.category)}</span>
        <span class="mono-text text-on-surface-variant">${c.count.toLocaleString()}</span>
      </div>
      <div class="h-2 bg-surface-container rounded-full overflow-hidden">
        <div class="h-full rounded-full" style="width:${pct}%;background:${color};opacity:0.85"></div>
      </div>
    </div>`;
  }).join('')}</div>`;
}

function svgGauge(percent) {
  const p = Math.max(0, Math.min(100, Number(percent) || 0));
  const color = p >= 70 ? AN_COLORS.app : p >= 40 ? AN_COLORS.newReg : AN_COLORS.error;
  return `<div class="flex items-center gap-4">
    <div class="text-4xl font-black mono-text" style="color:${color}">${p.toFixed(1)}<span class="text-lg ml-1 text-on-surface-variant">%</span></div>
    <div class="flex-1 h-3 bg-surface-container rounded-full overflow-hidden relative">
      <div class="h-full transition-all" style="width:${p}%;background:${color}"></div>
      <div class="absolute inset-y-0 left-[70%] w-px bg-on-surface-variant/40"></div>
    </div>
  </div>`;
}

function chartCard(title, body) {
  return `<div class="bg-surface-container-lowest rounded-xl p-5 border border-outline-variant/20 mb-4">
    <h4 class="text-sm font-bold tracking-tight mb-3">${escHtml(title)}</h4>
    ${body}
  </div>`;
}
