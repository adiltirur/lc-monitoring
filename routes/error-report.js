const router = require('express').Router();
const { ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { query } = require('../lib/db');
const { bedrockClient } = require('../lib/ai');

// ─── Routes: report – error report generator ─────────────────────────────────
router.post('/api/report/errors', async (req, res) => {
  try {
    const { range = 'day', date, dbHost, dbPort, dbName, dbUser, dbPassword } = req.body;
    if (!date) return res.status(400).json({ error: 'date is required (YYYY-MM-DD)' });

    // Allow credentials from body (used by form POST) as fallback to headers
    if (dbHost) req.headers['x-db-host'] = dbHost;
    if (dbPort) req.headers['x-db-port'] = String(dbPort);
    if (dbName) req.headers['x-db-name'] = dbName;
    if (dbUser) req.headers['x-db-user'] = dbUser;
    if (dbPassword) req.headers['x-db-password'] = dbPassword;

    // Compute Berlin-timezone date boundaries — `date` is always the END date
    const berlinOffset = '+02:00'; // close enough; actual DST handled by AT TIME ZONE in SQL
    const endDate = new Date(`${date}T23:59:59.999${berlinOffset}`);
    let startDate;
    if (range === 'day')         startDate = new Date(`${date}T00:00:00${berlinOffset}`);
    else if (range === 'week')   { startDate = new Date(endDate); startDate.setDate(startDate.getDate() - 6); startDate.setHours(0, 0, 0, 0); }
    else if (range === '2weeks') { startDate = new Date(endDate); startDate.setDate(startDate.getDate() - 13); startDate.setHours(0, 0, 0, 0); }
    else return res.status(400).json({ error: 'range must be day, week, or 2weeks' });

    const isMultiDay = range !== 'day';
    const timeBucket = isMultiDay
      ? `date_trunc('day', "time" AT TIME ZONE 'Europe/Berlin')`
      : `date_trunc('hour', "time")`;

    const [timeSeries, topEndpoints, totalRow, sampleErrors, topSlow, slowTotalRow, longLived] = await Promise.all([
      query(req, `
        SELECT ${timeBucket} AS bucket, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE "time" >= $1 AND "time" < $2 AND error IS NOT NULL
        GROUP BY 1 ORDER BY 1 ASC
      `, [startDate, endDate]),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
        GROUP BY endpoint ORDER BY count DESC LIMIT 15
      `, [startDate, endDate]),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2`, [startDate, endDate]),
      isMultiDay
        ? query(req, `
            SELECT DISTINCT ON (LEFT(error, 100)) id, "time", endpoint, method, duration, error, "stackTrace"
            FROM serverpod_session_log
            WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
            ORDER BY LEFT(error, 100), "time" DESC
            LIMIT 30
          `, [startDate, endDate])
        : query(req, `
            SELECT id, "time", endpoint, method, duration, error, "stackTrace"
            FROM serverpod_session_log
            WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
            ORDER BY "time" DESC LIMIT 50
          `, [startDate, endDate]),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE slow = true AND "time" >= $1 AND "time" < $2
        GROUP BY endpoint ORDER BY "avgMs" DESC LIMIT 15
      `, [startDate, endDate]),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE slow = true AND "time" >= $1 AND "time" < $2`, [startDate, endDate]),
      query(req, `
        SELECT endpoint, COALESCE(method, '') AS method,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE "time" >= $1 AND "time" < $2
          AND duration IS NOT NULL AND "isOpen" = false
        GROUP BY endpoint, method
        ORDER BY "avgMs" DESC LIMIT 15
      `, [startDate, endDate]),
    ]);

    const totalErrors = totalRow[0]?.count || 0;
    const totalSlow = slowTotalRow[0]?.count || 0;
    const peakBucket = timeSeries.reduce((a, b) => (b.count > (a?.count || 0) ? b : a), null);
    const peakLabel = peakBucket ? (isMultiDay
      ? new Date(peakBucket.bucket).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', timeZone: 'Europe/Berlin' })
      : `${String(new Date(peakBucket.bucket).getHours()).padStart(2, '0')}:00`) : '—';

    const startDateStr = startDate.toISOString().slice(0, 10);
    const rangeLabel = range === 'day' ? date : `${startDateStr} → ${date} (${range === 'week' ? '7' : '14'} days)`;

    // Build Bedrock prompt (only aggregates + sample messages — no full stack traces)
    const errorSummaryForAI = [
      `Period: ${rangeLabel}`,
      `Total errors: ${totalErrors}`,
      `Total slow sessions: ${totalSlow}`,
      `Peak: ${peakLabel} with ${peakBucket?.count || 0} errors`,
      `Top error endpoints: ${topEndpoints.slice(0, 8).map(e => `${e.endpoint}(${e.count})`).join(', ')}`,
      `Slow endpoint summaries: ${topSlow.slice(0, 5).map(e => `${e.endpoint} avg=${e.avgMs}ms max=${e.maxMs}ms`).join(', ')}`,
      `Sample error messages (first line only):`,
      ...sampleErrors.slice(0, 10).map(e => {
        const msg = (e.error || '').split('\n')[0].substring(0, 120)
          .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')  // emails
          .replace(/\b\d{5,}\b/g, '[id]')   // numeric IDs (5+ digits)
          .replace(/\+?\d[\d\s\-().]{7,}\d/g, '[phone]');  // phone numbers
        return `  [${e.endpoint || 'unknown'}] ${msg}`;
      }),
    ].join('\n');

    let aiSummary = '(AI analysis unavailable)';
    try {
      const aiRes = await bedrockClient.send(new ConverseCommand({
        modelId: 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0',
        system: [{ text: 'You are a DevOps engineer analyzing server errors and performance issues for the LillianCare healthcare platform. Summarize the errors, identify patterns and root causes, analyze slow endpoints, and give concise actionable recommendations. Use markdown-style sections: **Summary**, **Error Patterns**, **Performance Issues**, **Recommendations**. Be specific and brief.' }],
        messages: [{ role: 'user', content: [{ text: errorSummaryForAI }] }],
        inferenceConfig: { maxTokens: 1500, temperature: 0.2 },
      }));
      aiSummary = aiRes.output.message.content[0].text.trim();
    } catch (bedrockErr) {
      aiSummary = `(AI analysis failed: ${bedrockErr.message})`;
    }

    // Convert markdown to HTML
    const mdToHtml = md => {
      const esc2 = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const inline = s => s
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code style="background:var(--primary-fixed);padding:1px 4px;border-radius:3px;font-size:12px">$1</code>');

      const lines = md.split('\n');
      let html = '', inList = false, inOl = false, inTable = false;

      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        const trimmed = l.trim();

        // Table
        if (trimmed.startsWith('|')) {
          if (!inTable) { html += '<table style="width:100%;border-collapse:collapse;font-size:12px;margin:8px 0">'; inTable = true; }
          if (trimmed.replace(/[|\s-]/g, '') === '') continue; // separator row
          const cells = trimmed.split('|').filter((_,i,a) => i > 0 && i < a.length-1);
          const isHeader = lines[i-1]?.trim().startsWith('|') === false || i === 0;
          const tag = (i < lines.length-1 && lines[i+1]?.trim().replace(/[|\s-]/g,'') === '') ? 'th' : 'td';
          html += `<tr>${cells.map(c => `<${tag} style="padding:5px 8px;border:1px solid var(--outline-variant);text-align:left">${inline(c.trim())}</${tag}>`).join('')}</tr>`;
          continue;
        } else if (inTable) { html += '</table>'; inTable = false; }

        // Close lists
        if (inList && !trimmed.match(/^[-•*]\s/)) { html += '</ul>'; inList = false; }
        if (inOl && !trimmed.match(/^\d+\.\s/)) { html += '</ol>'; inOl = false; }

        if (!trimmed) continue;

        if (trimmed.match(/^#{1,3}\s/)) {
          const level = trimmed.match(/^#+/)[0].length;
          const text = trimmed.replace(/^#+\s*/, '');
          const sizes = ['15px','13px','12px'];
          html += `<div style="font-size:${sizes[level-1]||'12px'};font-weight:700;color:var(--primary);margin:${level===1?'12px':'8px'} 0 4px">${inline(esc2(text))}</div>`;
        } else if (trimmed.match(/^[-•*]\s/)) {
          if (!inList) { html += '<ul style="margin:4px 0;padding-left:18px">'; inList = true; }
          html += `<li style="margin:2px 0;color:var(--on-surface)">${inline(esc2(trimmed.replace(/^[-•*]\s*/,'')))}</li>`;
        } else if (trimmed.match(/^\d+\.\s/)) {
          if (!inOl) { html += '<ol style="margin:4px 0;padding-left:18px">'; inOl = true; }
          html += `<li style="margin:2px 0;color:var(--on-surface)">${inline(esc2(trimmed.replace(/^\d+\.\s*/,'')))}</li>`;
        } else {
          html += `<p style="margin:4px 0;color:var(--on-surface)">${inline(esc2(trimmed))}</p>`;
        }
      }
      if (inList) html += '</ul>';
      if (inOl) html += '</ol>';
      if (inTable) html += '</table>';
      return html;
    };
    const aiHtml = mdToHtml(aiSummary);

    // Chart data — single day: fill all 24 hours; multi-day: one point per day
    let chartLabels, chartValues;
    if (isMultiDay) {
      chartLabels = timeSeries.map(r => new Date(r.bucket).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', timeZone: 'Europe/Berlin' }));
      chartValues = timeSeries.map(r => r.count);
    } else {
      const countByHour = {};
      for (const r of timeSeries) countByHour[new Date(r.bucket).getUTCHours()] = r.count;
      chartLabels = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0') + ':00');
      chartValues = Array.from({ length: 24 }, (_, h) => countByHour[h] || 0);
    }

    const envLabel = (req.headers['x-db-host'] || 'unknown').split('.')[0];

    const escH = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const dur = secs => { if (secs == null) return '—'; const ms = secs * 1000; return fmtMs(ms); };
    const fmtMs = ms => { if (ms == null) return '—'; if (ms >= 3600000) return `${(ms/3600000).toFixed(1)}h`; if (ms >= 60000) return `${(ms/60000).toFixed(1)}m`; if (ms >= 1000) return `${(ms/1000).toFixed(1)}s`; return `${Math.round(ms)}ms`; };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LillianCare Error Report — ${escH(rangeLabel)}</title>
<style>
  :root {
    --primary: #3525cd;
    --primary-container: #4f46e5;
    --primary-fixed: #e2dfff;
    --on-primary: #ffffff;
    --surface: #f9f9f9;
    --surface-container-lowest: #ffffff;
    --surface-container-low: #f3f3f3;
    --surface-container: #eeeeee;
    --on-surface: #1a1c1c;
    --on-surface-variant: #464555;
    --outline: #777587;
    --outline-variant: #c7c4d8;
    --error: #ba1a1a;
    --error-container: #ffdad6;
    --on-error-container: #93000a;
    --success: #16a34a;
    --warning: #d97706;
    --badge-amber-bg: rgba(215,119,6,0.12);
    --badge-amber-text: #92400e;
    --sidebar-bg: #0f1a2e;
    --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-mono: 'JetBrains Mono', 'SF Mono', monospace;
    --shadow-card: 0 2px 8px rgba(26,28,28,0.05);
    --radius-default: 0.5rem;
    --radius-md: 0.75rem;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: var(--font-ui); background: var(--surface); color: var(--on-surface); margin: 0; padding: 24px; font-size: 14px; line-height: 1.5; }
  .wrapper { max-width: 860px; margin: 0 auto; }
  .hdr { background: linear-gradient(135deg, var(--sidebar-bg) 0%, #1a2d4a 100%); color: #e8f0fe; padding: 28px 32px; border-radius: var(--radius-md) var(--radius-md) 0 0; }
  .hdr h1 { margin: 0 0 4px; font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }
  .hdr .sub { font-size: 12px; color: rgba(232,240,254,0.55); margin: 0; }
  .hdr .env-badge { display: inline-block; background: rgba(79,70,229,0.2); color: var(--primary-fixed); border: 1px solid rgba(79,70,229,0.4); border-radius: var(--radius-default); padding: 2px 8px; font-size: 11px; font-weight: 600; margin-left: 10px; vertical-align: middle; text-transform: uppercase; letter-spacing: 1px; }
  .body { background: var(--surface-container-lowest); border-radius: 0 0 var(--radius-md) var(--radius-md); padding: 28px 32px; }
  .stats-row { display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 120px; background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); padding: 14px 16px; text-align: center; }
  .stat .val { font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; font-family: var(--font-mono); }
  .stat .lbl { font-size: 11px; color: var(--on-surface-variant); text-transform: uppercase; letter-spacing: 0.5px; }
  .val-red { color: var(--error); }
  .val-amber { color: var(--warning); }
  .val-blue { color: var(--primary-container); }
  .val-green { color: var(--success); }
  section { margin-bottom: 28px; }
  h2 { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: var(--on-surface-variant); margin: 0 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--outline-variant); }
  .ai-box { background: linear-gradient(135deg, var(--primary-fixed) 0%, #fafcff 100%); border: 1px solid rgba(79,70,229,0.2); border-radius: var(--radius-default); padding: 18px 20px; color: var(--on-surface); }
  .ai-box strong { color: var(--primary); }
  .ai-box li { color: var(--on-surface); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: var(--surface-container-low); color: var(--on-surface-variant); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--outline-variant); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--surface-container-low); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--surface-container-low); }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
  .badge-red { background: var(--error-container); color: var(--on-error-container); }
  .badge-amber { background: var(--badge-amber-bg); color: var(--badge-amber-text); }
  .err-row { margin-bottom: 10px; background: var(--surface-container-lowest); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); overflow: hidden; }
  .err-row-hdr { display: flex; gap: 12px; align-items: baseline; padding: 8px 12px; background: var(--surface-container-low); flex-wrap: wrap; }
  .err-time { font-size: 11px; color: var(--outline); font-family: var(--font-mono); }
  .err-ep { font-weight: 600; color: var(--primary-container); font-size: 12px; }
  .err-dur { font-size: 11px; color: var(--on-surface-variant); }
  .err-msg { padding: 6px 12px; font-family: var(--font-mono); font-size: 12px; color: var(--error); background: var(--surface-container-lowest); white-space: pre-wrap; word-break: break-all; }
  .err-stack { padding: 6px 12px 10px; font-family: var(--font-mono); font-size: 11px; color: var(--outline); background: var(--surface-container-lowest); white-space: pre-wrap; word-break: break-all; display: none; border-top: 1px solid var(--surface-container-low); }
  .toggle-stack { font-size: 11px; color: var(--primary-container); cursor: pointer; padding: 2px 12px 6px; display: block; background: var(--surface-container-lowest); border: none; text-align: left; }
  canvas { max-width: 100%; border-radius: var(--radius-default); }
  .chart-wrap { background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); padding: 16px; }
  .footer { margin-top: 24px; text-align: center; font-size: 11px; color: var(--outline); }
  @media (max-width: 600px) { body { padding: 12px; } .hdr, .body { padding: 18px; } .stats-row { gap: 10px; } }
</style>
</head>
<body>
<div class="wrapper">
  <div class="hdr">
    <h1>LillianCare Error Report <span class="env-badge">${escH(envLabel)}</span></h1>
    <p class="sub">Period: ${escH(rangeLabel)} &nbsp;·&nbsp; Generated: ${new Date().toLocaleString('de-DE', { timeZone: 'Europe/Berlin' })}</p>
  </div>
  <div class="body">
    <div class="stats-row">
      <div class="stat"><div class="val val-red">${totalErrors}</div><div class="lbl">Total Errors</div></div>
      <div class="stat"><div class="val val-amber">${topEndpoints.length}</div><div class="lbl">Error Endpoints</div></div>
      <div class="stat"><div class="val val-blue">${peakBucket?.count || 0}</div><div class="lbl">Peak ${isMultiDay ? 'Day' : 'Hour'} (${escH(peakLabel)})</div></div>
      <div class="stat"><div class="val val-amber">${totalSlow}</div><div class="lbl">Slow Sessions</div></div>
      <div class="stat"><div class="val val-blue">${longLived.length}</div><div class="lbl">Long-lived Endpoints</div></div>
    </div>

    <section>
      <h2>Error Trend — ${isMultiDay ? 'Daily' : 'Hourly'}</h2>
      <div class="chart-wrap"><canvas id="trendChart" height="120"></canvas></div>
      <table style="margin-top:12px">
        <thead><tr><th>${isMultiDay ? 'Date' : 'Hour'}</th><th>Errors</th></tr></thead>
        <tbody>${timeSeries.map((r, i) => `<tr><td>${escH(chartLabels[i])}</td><td>${r.count}</td></tr>`).join('')}</tbody>
      </table>
    </section>

    <section>
      <h2>AI Analysis</h2>
      <div class="ai-box">${aiHtml}</div>
      <details style="margin-top:10px">
        <summary style="cursor:pointer;font-size:11px;color:var(--outline);user-select:none;padding:4px 0">▶ View exact data sent to AI (for PII review)</summary>
        <pre style="margin-top:8px;background:var(--surface-container-low);border:1px solid var(--outline-variant);border-radius:var(--radius-default);padding:14px;font-size:11px;color:var(--on-surface-variant);white-space:pre-wrap;word-break:break-all;line-height:1.6">${escH(errorSummaryForAI)}</pre>
      </details>
    </section>

    <section>
      <h2>Top Error Endpoints</h2>
      <table>
        <thead><tr><th>Endpoint</th><th style="text-align:right">Errors</th></tr></thead>
        <tbody>${topEndpoints.map(e => `<tr><td>${escH(e.endpoint)}</td><td style="text-align:right"><span class="badge badge-red">${e.count}</span></td></tr>`).join('')}</tbody>
      </table>
    </section>

    ${topSlow.length ? `
    <section>
      <h2>Slow Sessions by Endpoint</h2>
      <div class="chart-wrap" style="margin-bottom:12px"><canvas id="slowChart" height="${Math.max(60, topSlow.length * 28)}"></canvas></div>
      <table>
        <thead><tr><th>Endpoint</th><th style="text-align:right">Count</th><th style="text-align:right">Avg</th><th style="text-align:right">Max</th></tr></thead>
        <tbody>${topSlow.map(e => `<tr><td>${escH(e.endpoint)}</td><td style="text-align:right">${e.count}</td><td style="text-align:right">${escH(fmtMs(e.avgMs))}</td><td style="text-align:right"><span class="badge badge-amber">${escH(fmtMs(e.maxMs))}</span></td></tr>`).join('')}</tbody>
      </table>
    </section>` : ''}

    ${longLived.length ? `
    <section>
      <h2>Long-lived Sessions by Endpoint</h2>
      <p style="font-size:12px;color:var(--on-surface-variant);margin:-4px 0 12px">Completed sessions sorted by average duration. WebSocket/streaming endpoints like <code>listenForQuestionnaires</code> will appear here — high duration is expected for these.</p>
      <table>
        <thead><tr><th>Endpoint</th><th>Method</th><th style="text-align:right">Count</th><th style="text-align:right">Avg Duration</th><th style="text-align:right">Max Duration</th></tr></thead>
        <tbody>${longLived.map(e => `<tr>
          <td>${escH(e.endpoint || 'unknown')}</td>
          <td style="color:var(--on-surface-variant);font-size:12px">${escH(e.method)}</td>
          <td style="text-align:right">${e.count}</td>
          <td style="text-align:right"><span class="badge badge-amber">${escH(fmtMs(e.avgMs))}</span></td>
          <td style="text-align:right">${escH(fmtMs(e.maxMs))}</td>
        </tr>`).join('')}</tbody>
      </table>
    </section>` : ''}

    <section>
      <h2>Error Details (${sampleErrors.length} sample${isMultiDay ? 's — distinct error types' : 's'})</h2>
      ${sampleErrors.map(e => `
      <div class="err-row">
        <div class="err-row-hdr">
          <span class="err-time">${escH(e.time ? new Date(e.time).toLocaleString('de-DE', { timeZone: 'Europe/Berlin' }) : '')}</span>
          <span class="err-ep">${escH(e.endpoint || 'unknown')}${e.method ? '#' + escH(e.method) : ''}</span>
          <span class="err-dur">${dur(e.duration)}</span>
        </div>
        <div class="err-msg">${escH((e.error || '').split('\n')[0].substring(0, 200))}</div>
        ${e.stackTrace ? `<button class="toggle-stack" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block';this.textContent=this.textContent==='▶ Show stack trace'?'▼ Hide stack trace':'▶ Show stack trace'">▶ Show stack trace</button><div class="err-stack">${escH((e.stackTrace || '').substring(0, 800))}</div>` : ''}
      </div>`).join('')}
    </section>

    <div class="footer">Generated by LC Monitor · ${new Date().toISOString()}</div>
  </div>
</div>

<script>
// Design token colors for canvas API (CSS vars don't work in canvas)
const C = {
  primary:     '#4f46e5',
  primaryFill: 'rgba(79,70,229,0.2)',
  outline:     '#777587',
  onSurface:   '#464555',
  onSurface2:  '#475569',
  barStart:    '#f97316',
  barEnd:      '#ef4444',
  white:       '#ffffff',
};

function drawCharts() {
  const labels = ${JSON.stringify(chartLabels)};
  const values = ${JSON.stringify(chartValues)};

  // Trend line chart
  const trendCanvas = document.getElementById('trendChart');
  if (trendCanvas && labels.length) {
    trendCanvas.width = (trendCanvas.parentElement.offsetWidth || 796) - 32;
    const ctx = trendCanvas.getContext('2d');
    const W = trendCanvas.width, H = trendCanvas.height;
    const maxV = Math.max(...values, 1);
    const padL = 40, padR = 16, padT = 16, padB = 28;
    const chartW = W - padL - padR, chartH = H - padT - padB;
    const step = chartW / Math.max(labels.length - 1, 1);

    ctx.clearRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = 'rgba(119,117,135,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padT + chartH - (i / 4) * chartH;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
      ctx.fillStyle = C.outline; ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
      ctx.fillText(Math.round((i / 4) * maxV), padL - 4, y + 3);
    }

    // Filled area
    const grad = ctx.createLinearGradient(0, padT, 0, padT + chartH);
    grad.addColorStop(0, C.primaryFill);
    grad.addColorStop(1, 'rgba(79,70,229,0)');
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(padL + (values.length - 1) * step, padT + chartH);
    ctx.lineTo(padL, padT + chartH);
    ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();

    // Line
    ctx.beginPath(); ctx.strokeStyle = C.primary; ctx.lineWidth = 2;
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Dots
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = C.primary; ctx.fill();
      ctx.fillStyle = C.white; ctx.beginPath(); ctx.arc(x, y, 1.5, 0, Math.PI * 2); ctx.fill();
    });

    // X labels (show max 12)
    ctx.fillStyle = C.outline; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
    const skip = Math.ceil(labels.length / 12);
    labels.forEach((l, i) => {
      if (i % skip === 0) ctx.fillText(l, padL + i * step, H - 4);
    });
  }

  // Slow endpoint horizontal bar chart
  const slowCanvas = document.getElementById('slowChart');
  const slowData = ${JSON.stringify(topSlow.slice(0, 10))};
  if (slowCanvas && slowData.length) {
    slowCanvas.width = (slowCanvas.parentElement.offsetWidth || 796) - 32;
    const ctx2 = slowCanvas.getContext('2d');
    const W = slowCanvas.width, H = slowCanvas.height;
    const maxAvg = Math.max(...slowData.map(d => d.avgMs), 1);
    const barH = Math.max(18, Math.floor((H - 8) / slowData.length) - 4);
    const padL = 140, padR = 60;

    ctx2.clearRect(0, 0, W, H);
    slowData.forEach((d, i) => {
      const y = 4 + i * (barH + 4);
      const barW = Math.max(2, ((d.avgMs / maxAvg) * (W - padL - padR)));

      // Label
      ctx2.fillStyle = C.onSurface; ctx2.font = '11px sans-serif'; ctx2.textAlign = 'right';
      const label = d.endpoint.length > 20 ? '...' + d.endpoint.slice(-18) : d.endpoint;
      ctx2.fillText(label, padL - 6, y + barH / 2 + 4);

      // Bar (avg)
      const grad2 = ctx2.createLinearGradient(padL, 0, padL + barW, 0);
      grad2.addColorStop(0, C.barStart);
      grad2.addColorStop(1, C.barEnd);
      ctx2.fillStyle = grad2;
      ctx2.beginPath();
      ctx2.roundRect ? ctx2.roundRect(padL, y, barW, barH, 3) : ctx2.rect(padL, y, barW, barH);
      ctx2.fill();

      // Value
      ctx2.fillStyle = C.onSurface2; ctx2.font = '11px sans-serif'; ctx2.textAlign = 'left';
      ctx2.fillText(d.avgMs + 'ms avg', padL + barW + 6, y + barH / 2 + 4);
    });
  }
}
// Run on load, then retry after 200ms in case offsetWidth was 0 (file:// URLs)
window.addEventListener('load', function() { drawCharts(); setTimeout(drawCharts, 200); });
</script>
</body>
</html>`;

    const filename = `lc-error-report-${rangeLabel.replace(/[^a-zA-Z0-9-]/g, '_')}.html`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(html);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
