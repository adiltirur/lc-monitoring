// API console: local state in .api-console/ (gitignored, dir 0700, files 0600).
//   accounts.json     LillianCare logins per env ({ id, env, label, email, password })
//   history.json      last requests as typed (never responses — they can hold patient data)
//   collections.json  saved requests, grouped in collections
//   vars.json         { global: {…}, dev: {…}, test: {…}, staging: {…}, production: {…} }
// Passwords are never sent back to the browser; see publicAccount().
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = path.join(__dirname, '..', '..', '.api-console');
const HISTORY_MAX = 300;
const ENVS = ['dev', 'test', 'staging', 'production'];

function file(name) { return path.join(DIR, `${name}.json`); }

function readJson(name, fallback) {
  try { return JSON.parse(fs.readFileSync(file(name), 'utf8')); } catch { return fallback; }
}

function writeJson(name, value) {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const tmp = file(name) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file(name));
}

const newId = () => crypto.randomBytes(6).toString('hex');

// ── accounts ──
function accounts() { return readJson('accounts', []); }
function account(id) { return accounts().find(a => a.id === id) || null; }
function publicAccount(a) { return { id: a.id, env: a.env, label: a.label, email: a.email, hasPassword: !!a.password }; }

function saveAccount(input) {
  if (!ENVS.includes(input.env)) throw Object.assign(new Error(`env must be one of ${ENVS.join(', ')}`), { status: 400 });
  if (!input.email) throw Object.assign(new Error('email is required'), { status: 400 });
  const list = accounts();
  const existing = input.id && list.find(a => a.id === input.id);
  const next = {
    id: existing ? existing.id : newId(),
    env: input.env,
    label: String(input.label || input.email).slice(0, 80),
    email: String(input.email).trim(),
    // Keep the stored password when the form leaves it empty.
    password: input.password ? String(input.password) : existing ? existing.password : '',
  };
  writeJson('accounts', existing ? list.map(a => (a.id === next.id ? next : a)) : [...list, next]);
  return next;
}

function deleteAccount(id) { writeJson('accounts', accounts().filter(a => a.id !== id)); }

// ── history ──
function history() { return readJson('history', []); }
function addHistory(entry) {
  writeJson('history', [{ id: newId(), at: new Date().toISOString(), ...entry }, ...history()].slice(0, HISTORY_MAX));
}
function clearHistory() { writeJson('history', []); }

// ── collections ──
function collections() { return readJson('collections', []); }
function saveCollections(list) {
  if (!Array.isArray(list)) throw Object.assign(new Error('collections must be an array'), { status: 400 });
  writeJson('collections', list);
}

// ── variables ──
function vars() {
  const v = readJson('vars', {});
  for (const k of ['global', ...ENVS]) if (!v[k] || typeof v[k] !== 'object') v[k] = {};
  return v;
}
function saveVars(v) {
  const clean = {};
  for (const k of ['global', ...ENVS]) {
    clean[k] = {};
    for (const [name, value] of Object.entries((v && v[k]) || {})) {
      if (/^[\w.-]+$/.test(name)) clean[k][name] = String(value);
    }
  }
  writeJson('vars', clean);
  return clean;
}

module.exports = {
  ENVS, accounts, account, publicAccount, saveAccount, deleteAccount,
  history, addHistory, clearHistory, collections, saveCollections, vars, saveVars,
};
