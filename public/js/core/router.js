// ═════════════════════════════════════════════════════════════════════════
// ROUTER
// ═════════════════════════════════════════════════════════════════════════
function navigate(view) {
  if (view === 'test-refresh') view = 'db-refresh'; // old bookmark
  window.__currentView = view;
  if (window.location.hash.replace('#', '') !== view) {
    window.__navFromCode = true;
    window.location.hash = view;
  }
  document.querySelectorAll('.lc-nav-item').forEach(el => el.classList.remove('active'));
  const active = document.querySelector(`.lc-nav-item[data-view="${view}"]`);
  if (active) active.classList.add('active');
  const content = document.getElementById('content');
  if (view === 'session-logs') renderSessionLogs(content);
  else if (view === 'admin-audit') renderAdminAudit(content);
  else if (view === 'notifications') renderNotifications(content);
  else if (view === 'message-outbox') renderMessageOutbox(content);
  else if (view === 'analytics') renderAnalytics(content);
  else if (view === 'users') renderUsers(content);
  else if (view === 'bookings') renderBookings(content);
  else if (view === 'query-runner') renderQueryRunner(content);
  else if (view === 'ai-query') renderAIQuery(content);
  else if (view === 'investigations') renderInvestigations(content);
  else if (view === 'api-console') renderApiConsole(content);
  else if (view === 'csv-decrypt') renderCsvDecrypt(content);
  else if (view === 'rds-restore') renderRdsRestore(content);
  else if (view === 'send-notification') renderSendNotification(content);
  else if (view === 'future-calls') renderFutureCalls(content);
  else if (view === 'health') renderHealth(content);
  else if (view === 'api-keys') renderApiKeys(content);
  else if (view === 'google-business') renderGoogleBusiness(content);
  else if (view === 'monitoring') renderMonitoring(content);
  else if (view === 'praxis-refresh') renderPraxisRefresh(content);
  else if (view === 'cockpit-fill') renderCockpitFill(content);
  else if (view === 'cockpit-sync') renderCockpitSync(content);
  else if (view === 'praxis-cleanup') renderPraxisCleanup(content);
  else if (view === 'personio-audit') renderPersonioAudit(content);
  else if (view === 'db-refresh') renderDbRefresh(content);
  else if (view === 'release') renderRelease(content);
  else if (view === 'ssh-tunnels') renderSshTunnels(content);
  else if (view === 'local-stack') renderLocalStack(content);
  else if (view === 'lilli') renderLilli(content);
  document.title = (TITLE_BY_VIEW[view] ? TITLE_BY_VIEW[view] + ' · ' : '') + 'LC Helper';
}
