// Shared by routes/lilli.js and routes/lilli-inv.js.
function lilliSend(res, e) {
  res.status(e.status || 500).json({ error: e.message });
}

module.exports = { lilliSend };
