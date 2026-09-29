// API console: the catalog of every Serverpod endpoint method, built live from
// LillianCare-Core's generated code so it never drifts from the backend.
//
// Sources (all read-only):
//   server  lib/src/generated/endpoints.dart   endpoints, methods, parameter types
//           lib/src/endpoints/**               requireLogin + method doc comments
//           lib/src/models/**/*.spy.yaml       model fields / enum values (body skeletons)
//           config/<mode>.yaml                 public API + web server URL per env
//   client  apps-frontend/.../client.dart      return types
//   modules ~/.pub-cache/.../serverpod_auth_*  auth module endpoints + models
//   shared  ../LillianCare-Shared-Models       Api* (freezed) classes used as params
//
// The catalog is rebuilt when endpoints.dart or client.dart change.
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..'); // helper/
const CORE_DIR = process.env.LC_CORE_DIR || path.join(ROOT, '..', 'LillianCare-Core');
const SERVER_DIR = process.env.LC_SERVERPOD_DIR || path.join(CORE_DIR, 'lillian_care_core_server');
const CLIENT_FILE = path.join(ROOT, '..', 'apps-frontend', 'packages', 'lillian_care_core_client', 'lib', 'src', 'protocol', 'client.dart');
const SHARED_MODELS_DIR = path.join(ROOT, '..', 'LillianCare-Shared-Models', 'lib');
const PUB_CACHE = process.env.PUB_CACHE || path.join(os.homedir(), '.pub-cache');
const ENDPOINTS_FILE = path.join(SERVER_DIR, 'lib', 'src', 'generated', 'endpoints.dart');

// Helper env → Serverpod run mode (config/<mode>.yaml).
const ENV_MODES = { dev: 'development', test: 'test', staging: 'staging', production: 'production' };

const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
const mtime = (p) => { try { return fs.statSync(p).mtimeMs; } catch { return 0; } };
const stripAlias = (t) => t.replace(/_i\d+\./g, '').replace(/\s+/g, ' ').trim();

function walk(dir, test, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== 'generated' && !e.name.startsWith('.')) walk(p, test, out); }
    else if (test(e.name)) out.push(p);
  }
  return out;
}

// ─── generated endpoints.dart ────────────────────────────────────────────────
// connectors['x'] = EndpointConnector(... methodConnectors: { 'm': MethodConnector(
//   params: { 'p': ParameterDescription(name: 'p', type: getType<T>(), nullable: b) } ...
function parseEndpointsDart(src, prefix = '') {
  const endpoints = [];
  const blocks = src.split(/connectors\['/).slice(1);
  for (const block of blocks) {
    const name = block.slice(0, block.indexOf("'"));
    const methods = [];
    const mre = /'(\w+)': _i\d+\.(MethodConnector|MethodStreamConnector)\(/g;
    const starts = [];
    let m;
    while ((m = mre.exec(block))) starts.push({ name: m[1], stream: m[2] === 'MethodStreamConnector', at: m.index });
    starts.forEach((s, i) => {
      const body = block.slice(s.at, i + 1 < starts.length ? starts[i + 1].at : block.length);
      const paramsPart = body.split(/\bcall:|streamParams:/)[0];
      const params = [];
      const pre = /ParameterDescription\(\s*name: '(\w+)',\s*type: _i\d+\.getType<([\s\S]+?)>\(\),\s*nullable: (true|false)/g;
      let p;
      while ((p = pre.exec(paramsPart))) params.push({ name: p[1], type: stripAlias(p[2]), nullable: p[3] === 'true' });
      methods.push({ name: s.name, params, streaming: s.stream });
    });
    endpoints.push({ name: prefix + name, methods });
  }
  return endpoints;
}

// endpoints map: 'twoFactor': _i2.TwoFactorEndpoint()  +  import '../endpoints/x.dart' as _i2;
function endpointSourceFiles(src, generatedDir) {
  const aliasFile = {};
  for (const m of src.matchAll(/import\s+'([^']+)'\s+as\s+(_i\d+);/g)) {
    if (!m[1].startsWith('package:')) aliasFile[m[2]] = path.resolve(generatedDir, m[1]);
  }
  const files = {};
  for (const m of src.matchAll(/'(\w+)': (_i\d+)\.\w+\(\)\s*\.\.initialize/g)) files[m[1]] = aliasFile[m[2]];
  return files;
}

// requireLogin and the /// doc comment directly above each method.
function endpointSourceInfo(file) {
  const src = file && read(file);
  if (!src) return { requireLogin: null, docs: {} };
  const docs = {};
  const re = /((?:[ \t]*\/\/\/[^\n]*\n)+)(?:[ \t]*@\w+[^\n]*\n)*[ \t]*(?:Future|Stream)<[\s\S]*?>\s+(\w+)\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    docs[m[2]] = m[1].split('\n').map(l => l.replace(/^\s*\/\/\/ ?/, '')).join('\n').trim();
  }
  return { requireLogin: /requireLogin\s*=>\s*true/.test(src), docs };
}

// client.dart: callServerEndpoint<T>('endpoint', 'method', ...)
function parseReturnTypes(src, out = {}) {
  if (!src) return out;
  const re = /call(Streaming)?ServerEndpoint<([\s\S]*?)>\(\s*'([\w.]+)',\s*'(\w+)'/g;
  let m;
  while ((m = re.exec(src))) out[`${m[3]}.${m[4]}`] = stripAlias(m[2]);
  return out;
}

// ─── models (.spy.yaml) ──────────────────────────────────────────────────────
function splitTop(s, sep = ',') {
  const out = []; let depth = 0, cur = '';
  for (const ch of s) {
    if ('<({['.includes(ch)) depth++;
    if ('>)}]'.includes(ch)) depth--;
    if (ch === sep && depth === 0) { out.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map(x => x.trim());
}

function parseSpyYaml(src, models) {
  const kind = (src.match(/^(class|enum|exception):\s*(\w+)/m) || [])[1];
  const name = (src.match(/^(?:class|enum|exception):\s*(\w+)/m) || [])[1];
  if (!name) return;
  if (kind === 'enum') {
    const serialized = (src.match(/^serialized:\s*(\w+)/m) || [])[1] || 'byName';
    const valuesPart = src.split(/^values:\s*$/m)[1] || '';
    const values = [];
    for (const line of valuesPart.split('\n')) {
      if (/^\S/.test(line) && line.trim()) break;
      const v = line.match(/^\s*-\s*(\w+)/);
      if (v) values.push(v[1]);
    }
    models[name] = { kind: 'enum', serialized, values };
    return;
  }
  const fields = [];
  if (/^table:/m.test(src)) fields.push({ name: 'id', type: 'int?' });
  const fieldsPart = src.split(/^fields:\s*$/m)[1] || '';
  for (const line of fieldsPart.split('\n')) {
    if (/^\S/.test(line) && line.trim()) break;
    const f = line.match(/^ {2}(\w+):\s*(.+?)\s*$/);
    if (!f) continue;
    const [type, ...opts] = splitTop(f[2]);
    if (opts.some(o => /scope\s*=\s*serverOnly/.test(o))) continue;
    fields.push({ name: f[1], type: type.replace(/^module:\w+:/, '') });
  }
  models[name] = { kind, fields };
}

// Freezed Api* classes: const factory X({ required T a, @JsonKey(name: 'b') T? c, ... }) = _X;
function parseFreezedDart(src, models) {
  for (const m of src.matchAll(/enum\s+(\w+)\s*\{([^}]*)\}/g)) {
    const values = m[2].split(';')[0].split(',').map(v => v.replace(/@\w+(\([^)]*\))?/g, '').trim().split(/[\s(]/)[0]).filter(Boolean);
    models[m[1]] = { kind: 'enum', serialized: 'byName', values };
  }
  for (const m of src.matchAll(/const\s+factory\s+(\w+)\s*\(\s*\{([\s\S]*?)\}\s*\)\s*=/g)) {
    const fields = [];
    for (let part of splitTop(m[2])) {
      const key = (part.match(/@JsonKey\([^)]*name:\s*'([^']+)'/) || [])[1];
      part = part.replace(/@\w+(\((?:[^()]|\([^()]*\))*\))?/g, '').replace(/\brequired\b/, '').trim();
      const fm = part.match(/^(.+?)\s+(\w+)$/);
      if (fm) fields.push({ name: key || fm[2], type: fm[1].trim() });
    }
    models[m[1]] = { kind: 'class', fields };
  }
}

// ─── body skeletons ──────────────────────────────────────────────────────────
function skeleton(type, models, depth = 0, seen = new Set()) {
  type = type.trim();
  if (type.endsWith('?')) return depth === 0 ? skeleton(type.slice(0, -1), models, depth, seen) : null;
  const g = type.match(/^(\w+)<([\s\S]+)>$/);
  if (g) {
    const args = splitTop(g[2]);
    if (g[1] === 'List' || g[1] === 'Set') return depth > 4 ? [] : [skeleton(args[0], models, depth + 1, seen)];
    if (g[1] === 'Map') {
      const v = depth > 4 ? null : skeleton(args[1] || 'dynamic', models, depth + 1, seen);
      return /^String\??$/.test(args[0]) ? { key: v } : [{ k: skeleton(args[0], models, depth + 1, seen), v }];
    }
    return null;
  }
  switch (type) {
    case 'String': return '';
    case 'int': return 0;
    case 'double': case 'num': return 0.0;
    case 'bool': return false;
    case 'DateTime': return new Date().toISOString();
    case 'Duration': return 0;
    case 'UuidValue': return '00000000-0000-4000-8000-000000000000';
    case 'BigInt': return '0';
    case 'Uri': return 'https://';
    case 'ByteData': return '';
    case 'dynamic': case 'Object': return null;
  }
  const model = models[type];
  if (!model) return {};
  if (model.kind === 'enum') return model.serialized === 'byIndex' ? 0 : (model.values[0] || '');
  if (seen.has(type) || depth > 4) return {};
  const next = new Set(seen).add(type);
  const obj = {};
  for (const f of model.fields) obj[f.name] = skeleton(f.type, models, depth + 1, next);
  return obj;
}

// Model types referenced by a type string (for the docs panel).
function referencedModels(type, models) {
  return [...new Set(type.match(/\b[A-Z]\w+/g) || [])].filter(t => models[t]);
}

// ─── config/<mode>.yaml → public URLs ────────────────────────────────────────
function serverUrls() {
  const out = {};
  for (const [env, mode] of Object.entries(ENV_MODES)) {
    const src = read(path.join(SERVER_DIR, 'config', `${mode}.yaml`)) || '';
    const section = (name) => {
      const part = src.split(new RegExp(`^${name}:\\s*$`, 'm'))[1] || '';
      const get = (k) => (part.match(new RegExp(`^\\s+${k}:\\s*(\\S+)`, 'm')) || [])[1];
      const scheme = get('publicScheme'), host = get('publicHost'), port = get('publicPort');
      if (!host) return null;
      const std = (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80');
      return `${scheme}://${host}${std || !port ? '' : ':' + port}`;
    };
    out[env] = { coreApi: section('apiServer'), coreWeb: section('webServer') };
  }
  return out;
}

// ─── modules (serverpod_auth*) ───────────────────────────────────────────────
function lockedVersion(pkg) {
  const lock = read(path.join(SERVER_DIR, 'pubspec.lock')) || '';
  const m = lock.match(new RegExp(`\\n  ${pkg}:\\n(?:    .*\\n)*?    version: "([^"]+)"`));
  return m && m[1];
}

function moduleEndpoints(appSrc, models, returns) {
  const out = [];
  for (const m of appSrc.matchAll(/modules\['(\w+)'\]/g)) {
    const mod = m[1];
    const ver = lockedVersion(`${mod}_server`);
    if (!ver) continue;
    const pkgDir = path.join(PUB_CACHE, 'hosted', 'pub.dev', `${mod}_server-${ver}`);
    const src = read(path.join(pkgDir, 'lib', 'src', 'generated', 'endpoints.dart'));
    for (const f of walk(path.join(pkgDir, 'lib'), n => n.endsWith('.spy.yaml'))) parseSpyYaml(read(f), models);
    const clientDir = path.join(PUB_CACHE, 'hosted', 'pub.dev', `${mod}_client-${ver}`);
    for (const f of walk(path.join(clientDir, 'lib'), n => n === 'client.dart')) parseReturnTypes(read(f), returns);
    if (!src) continue;
    for (const ep of parseEndpointsDart(src, `${mod}.`)) out.push({ ...ep, module: mod });
  }
  return out;
}

// ─── build ───────────────────────────────────────────────────────────────────
let cache = null;

function buildCatalog() {
  const appSrc = read(ENDPOINTS_FILE);
  if (!appSrc) throw new Error(`Serverpod endpoints not found at ${ENDPOINTS_FILE} (set LC_CORE_DIR)`);
  const models = {};
  for (const f of walk(SHARED_MODELS_DIR, n => n.endsWith('.dart') && !/\.(g|freezed)\.dart$/.test(n))) parseFreezedDart(read(f), models);
  for (const f of walk(path.join(SERVER_DIR, 'lib'), n => n.endsWith('.spy.yaml'))) parseSpyYaml(read(f), models);
  const returns = parseReturnTypes(read(CLIENT_FILE));
  const sources = endpointSourceFiles(appSrc, path.dirname(ENDPOINTS_FILE));

  const endpoints = parseEndpointsDart(appSrc).map(ep => {
    const info = endpointSourceInfo(sources[ep.name]);
    return { ...ep, requireLogin: info.requireLogin, source: sources[ep.name] ? path.relative(CORE_DIR, sources[ep.name]) : null, docs: info.docs };
  }).concat(moduleEndpoints(appSrc, models, returns).map(ep => ({ ...ep, requireLogin: null, docs: {} })));

  const out = endpoints.map(ep => ({
    name: ep.name,
    module: ep.module || null,
    requireLogin: ep.requireLogin,
    source: ep.source || null,
    methods: ep.methods.map(m => {
      const body = {};
      for (const p of m.params) body[p.name] = p.nullable ? null : skeleton(p.type, models);
      const types = new Set();
      for (const p of m.params) referencedModels(p.type, models).forEach(t => types.add(t));
      return {
        name: m.name,
        streaming: m.streaming,
        params: m.params,
        returns: returns[`${ep.name}.${m.name}`] || null,
        doc: ep.docs[m.name] || '',
        body,
        types: [...types],
      };
    }).sort((a, b) => a.name.localeCompare(b.name)),
  })).sort((a, b) => (!!a.module - !!b.module) || a.name.localeCompare(b.name));

  // Only ship the models the catalog refers to (plus their nested fields).
  const needed = new Set();
  const add = (t) => {
    if (needed.has(t) || !models[t]) return;
    needed.add(t);
    for (const f of models[t].fields || []) referencedModels(f.type, models).forEach(add);
  };
  for (const ep of out) for (const m of ep.methods) {
    m.types.forEach(add);
    if (m.returns) referencedModels(m.returns, models).forEach(add);
  }
  const usedModels = {};
  for (const t of [...needed].sort()) usedModels[t] = models[t];

  return {
    builtAt: new Date().toISOString(),
    coreDir: CORE_DIR,
    endpoints: out,
    models: usedModels,
    urls: serverUrls(),
    counts: {
      endpoints: out.length,
      methods: out.reduce((n, e) => n + e.methods.length, 0),
    },
  };
}

function getCatalog() {
  const stamp = `${mtime(ENDPOINTS_FILE)}:${mtime(CLIENT_FILE)}`;
  if (!cache || cache.stamp !== stamp) cache = { stamp, data: buildCatalog() };
  return cache.data;
}

module.exports = { getCatalog, serverUrls, ENV_MODES };
