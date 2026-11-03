const $ = (id) => document.getElementById(id);
const CSRF = document.querySelector('meta[name="gonuts-csrf"]').content;
let current = null, toastTimer = 0, countdown = 0;

async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set('X-Gonuts-Csrf', CSRF);
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const r = await fetch(path, { ...opts, headers, credentials: 'same-origin' });
  if (r.status === 401) { location.href = '/dashboard'; throw new Error('signed out'); }
  let data = null;
  try { data = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((data && data.message) || ('HTTP ' + r.status));
  return data;
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function money(v) {
  if (v == null || !Number.isFinite(Number(v))) return '—';
  const n = Number(v), a = Math.abs(n), sign = n < 0 ? '-' : '';
  if (a >= 1e9) return sign + '$' + (a / 1e9).toFixed(2) + 'b';
  if (a >= 1e6) return sign + '$' + (a / 1e6).toFixed(2) + 'm';
  if (a >= 1e3) return sign + '$' + (a / 1e3).toFixed(1) + 'k';
  return sign + '$' + Math.round(a);
}
function compact(v) { if (v == null) return '—'; const a = Math.abs(Number(v)); return a >= 1e6 ? (Number(v)/1e6).toFixed(1)+'m' : a >= 1e3 ? (Number(v)/1e3).toFixed(1)+'k' : String(v); }
function ago(ms) {
  if (!ms) return 'never';
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function interval(v) { return v && v.h24 != null ? v.h24 : null; }
function source(v) { return v && v.source ? v.source : 'booked'; }
function stateClass(state) { return state === 'STOPPED' ? 'bad' : state === 'PAUSED' ? 'paused' : ''; }
function row(label, value, full) {
  const d = el('div', 'kv' + (full ? ' full' : ''));
  d.append(el('dt', '', label), el('dd', '', value == null ? '—' : String(value)));
  return d;
}
function card(inst) {
  const t = inst.telemetry || {};
  const article = el('article', 'card');
  const head = el('div', 'card-head');
  head.append(el('h2', '', inst.name || 'GoNuts client'));
  head.append(el('span', 'pill' + (inst.online ? '' : ' offline'), inst.online ? 'online' : 'offline'));
  article.append(head);

  const stateRow = el('div', 'state-row');
  stateRow.append(el('div', 'mascot face-' + (t.mascotFace || 'IDLE')));
  const stateBox = el('div');
  const state = t.state || (inst.online ? 'UNKNOWN' : 'OFFLINE');
  stateBox.append(el('div', 'state ' + stateClass(state), state + (t.detail ? ' · ' + t.detail : '')));
  stateBox.append(el('div', 'state-detail', t.lastAction ? 'last: ' + t.lastAction + ' · ' + ago(t.lastActionAt) : 'Waiting for activity'));
  stateRow.append(stateBox);
  article.append(stateRow);

  const rows = el('section', 'rows');
  rows.append(row('account', t.account || '—'));
  rows.append(row('bank', t.bank == null ? '—' : money(t.bank)));
  rows.append(row('profit 1h', t.profit && t.profit.h1 != null ? money(t.profit.h1) : '—'));
  rows.append(row('profit 24h', t.profit && t.profit.h24 != null ? money(t.profit.h24) : '—'));
  rows.append(row('sales 1h / 24h', (t.sales && t.sales.h1 != null ? compact(t.sales.h1) : '—') + ' / ' + (t.sales && t.sales.h24 != null ? compact(t.sales.h24) : '—')));
  rows.append(row('purchases 24h', t.purchases && t.purchases.h24 != null ? compact(t.purchases.h24) : '—'));
  rows.append(row('listings 24h', t.listings && t.listings.h24 != null ? compact(t.listings.h24) : '—'));
  rows.append(row('reprices 24h', t.reprices && t.reprices.h24 != null ? compact(t.reprices.h24) : '—'));
  rows.append(row('listed / slots', (t.listed == null ? '—' : t.listed) + ' / ' + (t.slots == null ? '—' : t.slots), true));
  rows.append(row('trades (session)', t.trades == null ? '—' : t.trades, true));
  rows.append(row('profit source', source(t.profit), true));
  article.append(rows);

  const swarm = el('div', 'swarm');
  swarm.append(el('span', 'tag', 'Swarm'));
  const enabled = t.swarm && t.swarm.enabled;
  swarm.append(el('span', enabled ? 'on' : 'off', enabled ? 'sharing market observations' : 'not sharing'));
  swarm.append(el('span', '', '· guidance ' + (t.swarm && t.swarm.guidanceEnabled ? 'on' : 'off')));
  swarm.append(el('span', '', '· ' + (t.swarm && t.swarm.eligible ? 'eligible' : 'not eligible')));
  article.append(swarm);

  const actions = el('div', 'actions');
  const open = el('button', 'btn gold', 'Open panel');
  open.onclick = () => { location.href = '/dashboard/panel/' + inst.id + '/'; };
  const pause = el('button', 'btn', 'Pause');
  pause.disabled = !inst.online || !(t.controls ? t.controls.pause : false);
  pause.onclick = () => command(inst.id, 'pause');
  const resume = el('button', 'btn', 'Resume');
  resume.disabled = !inst.online || !(t.controls ? t.controls.resume : false);
  resume.onclick = () => command(inst.id, 'resume');
  const refresh = el('button', 'btn', 'Refresh');
  refresh.disabled = !inst.online;
  refresh.onclick = () => command(inst.id, 'snapshot');
  actions.append(open, pause, resume, refresh);
  article.append(actions);

  const foot = el('div', 'card-foot');
  foot.append(el('span', '', t.build || inst.build || 'unknown build'));
  foot.append(el('span', '', 'seen ' + ago(inst.lastSeen)));
  const links = el('div', 'links');
  const rename = el('button', 'link', 'rename');
  rename.onclick = () => renameInst(inst);
  const unlink = el('button', 'link', 'unlink');
  unlink.onclick = () => unlinkInst(inst);
  links.append(rename, unlink);
  foot.append(links);
  article.append(foot);

  if (inst.lastCommand && inst.lastCommand.state && !['completed'].includes(inst.lastCommand.state)) {
    article.append(el('div', 'muted', 'Last command: ' + inst.lastCommand.command + ' · ' + inst.lastCommand.state + (inst.lastCommand.reason ? ' · ' + inst.lastCommand.reason : '')));
  }
  return article;
}
function render(data) {
  current = data;
  $('who').textContent = data.user.globalName || data.user.username || '';
  const cards = $('cards');
  cards.replaceChildren(...data.installations.map(card));
  $('empty').hidden = data.installations.length > 0;
  const hive = $('hive');
  hive.replaceChildren();
  if (data.hives && data.hives.length) {
    const count = data.hives.reduce((n, h) => n + h.count, 0);
    hive.hidden = false;
    hive.append(el('span', '', 'You have ' + count + ' linked bot' + (count === 1 ? '' : 's') + '.'));
    hive.append(el('span', 'spacer'));
    const pauseAll = el('button', 'btn', 'Pause all');
    pauseAll.onclick = () => data.installations.filter(i => i.online).forEach(i => command(i.id, 'pause'));
    const resumeAll = el('button', 'btn', 'Resume all');
    resumeAll.onclick = () => data.installations.filter(i => i.online).forEach(i => command(i.id, 'resume'));
    hive.append(pauseAll, resumeAll);
  } else hive.hidden = true;
}
async function load() {
  try { render(await api('/dashboard/api/state', { cache: 'no-store' })); }
  catch (e) { toast(e.message, true); }
}
async function command(id, cmd) {
  try { await api('/dashboard/api/installations/' + id + '/command', { method: 'POST', body: JSON.stringify({ command: cmd }) }); toast(cmd + ' sent'); setTimeout(load, 400); }
  catch (e) { toast(e.message, true); }
}
async function renameInst(inst) {
  const name = prompt('Client label', inst.name || '');
  if (name == null || !name.trim()) return;
  try { await api('/dashboard/api/installations/' + inst.id + '/rename', { method: 'POST', body: JSON.stringify({ name: name.trim() }) }); toast('Renamed'); load(); }
  catch (e) { toast(e.message, true); }
}
async function unlinkInst(inst) {
  if (!confirm('Unlink ' + (inst.name || 'this client') + '? The bot will stop connecting.')) return;
  try { await api('/dashboard/api/installations/' + inst.id, { method: 'DELETE' }); toast('Unlinked'); load(); }
  catch (e) { toast(e.message, true); }
}
function toast(text, bad) {
  const t = $('toast'); t.textContent = text; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.hidden = true, 4000);
}
async function linkClient() {
  try {
    const p = await api('/dashboard/api/pair/code', { method: 'POST' });
    $('code').textContent = p.code;
    $('modal').hidden = false;
    countdown = Math.max(0, Math.floor((p.expiresAt - Date.now()) / 1000));
    const tick = () => {
      if ($('modal').hidden) return;
      $('codeExpiry').textContent = countdown > 0 ? 'Expires in ' + Math.floor(countdown / 60) + ':' + String(countdown % 60).padStart(2, '0') : 'Code expired — create a new one';
      countdown--; setTimeout(tick, 1000);
    };
    tick();
  } catch (e) { toast(e.message, true); }
}
$('linkClient').onclick = linkClient;
$('closeModal').onclick = () => { $('modal').hidden = true; load(); };
$('copyCode').onclick = async () => { try { await navigator.clipboard.writeText($('code').textContent); toast('Copied'); } catch (e) { toast('Copy failed', true); } };

let sse = null;
function connect() {
  sse = new EventSource('/dashboard/events');
  sse.addEventListener('update', () => load());
  sse.onerror = () => { sse.close(); setTimeout(connect, 5000); };
}
load(); connect();
// Poll as well as stream: the hub's Updates() channel is single-consumer, so a
// second tab can miss an event that another tab consumed.
setInterval(load, 15000);
// Refresh relative timestamps without refetching.
setInterval(() => { if (current) render(current); }, 10000);
