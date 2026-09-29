// ═════════════════════════════════════════════════════════════════════════
// MONITOR
// ═════════════════════════════════════════════════════════════════════════
function renderMonitoring(el) {
  el.innerHTML = `<iframe src="/monitoring.html" allowfullscreen style="width:100%;height:calc(100vh - 40px);border:0;display:block"></iframe>`;
}

// ═════════════════════════════════════════════════════════════════════════
// CSV DECRYPTOR
// ═════════════════════════════════════════════════════════════════════════
function renderCsvDecrypt(el) {
  el.innerHTML = `<iframe src="/tools/decrypt_viewer.html" style="width:100%;height:calc(100vh - 40px);border:0;display:block;background:var(--bg)"></iframe>`;
}

function renderRdsRestore(el) {
  el.innerHTML = `<iframe src="/tools/aws_rds_restore.html" style="width:100%;height:calc(100vh - 40px);border:0;display:block;background:var(--bg)"></iframe>`;
}
