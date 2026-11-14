const $ = (id) => document.getElementById(id);
const CSRF = document.querySelector('meta[name="gonuts-csrf"]').content;
let current = null, toastTimer = 0, countdown = 0;
let viewMode = localStorage.getItem('gonuts.viewMode') || 'split';
let scope = localStorage.getItem('gonuts.scope') || 'all';
let maskNames = localStorage.getItem('gonuts.mask') === '1';
function displayName(inst, i) { return maskNames ? 'Account ' + (i + 1) : (inst.name || 'GoNuts client'); }

async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set('X-Gonuts-Csrf', CSRF);
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const r = await fetch(path, { ...opts, headers, credentials: 'same-origin' });
  if (r.status === 401) { location.href = '/dashboard'; throw new Error('signed out'); }
  if (r.status === 403 && !sessionStorage.getItem('gonuts.csrf-reload')) {
    sessionStorage.setItem('gonuts.csrf-reload', '1');
    location.reload();
    throw new Error('refreshing session');
  }
  let data = null;
  try { data = await r.json(); } catch (e) {}
  if (r.ok) sessionStorage.removeItem('gonuts.csrf-reload');
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
function stateClass(state) { return state === 'STOPPED' || state === 'OFFLINE' ? 'bad' : state === 'PAUSED' ? 'paused' : ''; }
function row(label, value, full) {
  const d = el('div', 'kv' + (full ? ' full' : ''));
  d.append(el('dt', '', label), el('dd', '', value == null ? '—' : String(value)));
  return d;
}
function card(inst, index) {
  const t = inst.telemetry || {};
  const article = el('article', 'card');
  const head = el('div', 'card-head');
  head.append(el('h2', '', displayName(inst, index)));
  head.append(el('span', 'pill' + (inst.online ? '' : ' offline'), inst.online ? 'online' : 'offline'));
  article.append(head);

  const stateRow = el('div', 'state-row');
  stateRow.append(el('div', 'mascot face-' + (t.mascotFace || 'IDLE')));
  const stateBox = el('div');
  const state = inst.online ? (t.state || 'UNKNOWN') : 'OFFLINE';
  const detail = inst.online && t.detail ? ' · ' + t.detail : '';
  stateBox.append(el('div', 'state ' + stateClass(state), state + detail));
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
  rows.append(row('listings 1h', t.listings && t.listings.h1 != null ? compact(t.listings.h1) : '—'));
  rows.append(row('reprices 1h', t.reprices && t.reprices.h1 != null ? compact(t.reprices.h1) : '—'));
  rows.append(row('listed / slots', (t.listed == null ? '—' : t.listed) + ' / ' + (t.slots == null ? '—' : t.slots)));
  rows.append(row('trades (session)', t.trades == null ? '—' : t.trades));
  rows.append(row('profit source', source(t.profit), true));
  article.append(rows);

  if (t.swarm && t.swarm.enabled) {
    const swarm = el('div', 'swarm');
    swarm.append(el('span', 'tag', 'Swarm'));
    swarm.append(el('span', 'on', 'sharing market observations'));
    swarm.append(el('span', '', '· guidance ' + (t.swarm.guidanceEnabled ? 'on' : 'off')));
    swarm.append(el('span', '', '· ' + (t.swarm.eligible ? 'eligible' : 'not eligible')));
    article.append(swarm);
  }

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
function total(items, pick) {
  let n = 0, any = false;
  for (const item of items) {
    const v = pick(item);
    if (v == null || !Number.isFinite(Number(v))) continue;
    n += Number(v); any = true;
  }
  return any ? n : null;
}
function stat(label, value, note, cls) {
  const d = el('div', 'stat' + (cls ? ' ' + cls : ''));
  d.append(el('span', 'label', label), el('b', '', value == null ? '—' : String(value)), el('small', '', note || ''));
  return d;
}
function rate(value) { return value == null ? null : (Math.round(value * 10) / 10).toFixed(1); }
function perHourNote(value) { return value == null ? '' : ' · ' + money(value / 24) + '/h'; }
function perHourCount(value) { return value == null ? '' : ' · ' + rate(value / 24) + '/h'; }
function statElements(items) {
  const t = items.map(i => i.telemetry || {});
  const profit1 = total(t, x => x.profit?.h1), profit24 = total(t, x => x.profit?.h24);
  const revenue1 = total(t, x => x.revenue?.h1), revenue24 = total(t, x => x.revenue?.h24);
  const sales1 = total(t, x => x.sales?.h1), sales24 = total(t, x => x.sales?.h24);
  const margin = profit24 != null && revenue24 != null && revenue24 > 0 ? (profit24 / revenue24 * 100).toFixed(1) + '%' : null;
  return [
    stat('Bank now', money(total(t, x => x.bank)), 'a balance, not profit', 'gold'),
    stat('Profit last 24h', money(profit24), 'booked by your hive' + perHourNote(profit24), 'good'),
    stat('Sales records last 24h', compact(sales24), 'booked sales, not unique trades' + perHourCount(sales24)),
    stat('Profit last hour', money(profit1), 'booked', 'good'),
    stat('Sales records last hour', compact(sales1), 'booked'),
    stat('Profit margin 24h', margin, 'profit / sales revenue'),
    stat('Sales revenue last 24h', money(revenue24), 'gross booked sales' + perHourNote(revenue24)),
    stat('Sales revenue last hour', money(revenue1), 'gross booked sales')
  ];
}
function selectedInstallations(data) {
  const all = data.installations || [];
  return scope === 'all' ? all : all.filter(i => String(i.id) === String(scope));
}
function renderHive(data) {
  const all = data.installations || [];
  if (!all.length) { $('hiveOverview').hidden = true; $('splitStats').hidden = true; return; }
  $('hiveOverview').hidden = viewMode !== 'hive';
  $('splitStats').hidden = viewMode !== 'split';
  if (scope !== 'all' && !all.some(i => String(i.id) === String(scope))) scope = 'all';
  const selected = selectedInstallations(data);
  const online = selected.filter(i => i.online);
  const sel = $('scope');
  const shape = all.map(i => i.id + ':' + (i.name || '') + ':' + (i.online ? 1 : 0)).join('|');
  if (sel.dataset.shape !== shape) {
    sel.replaceChildren();
    sel.append(new Option('All accounts', 'all'));
    all.forEach((i, idx) => sel.append(new Option(displayName(i, idx) + (i.online ? '' : ' (offline)'), String(i.id))));
    sel.dataset.shape = shape;
  }
  sel.value = scope;
  $('hiveName').textContent = scope === 'all'
    ? all.length + ' account' + (all.length === 1 ? '' : 's') + ' · ' + all.filter(i => i.online).length + ' online'
    : (selected[0] ? displayName(selected[0], all.indexOf(selected[0])) : '—');
  $('hiveScopeNote').textContent = scope === 'all'
    ? (online.length === selected.length ? 'Controlling all accounts' : 'Controlling online accounts')
    : 'Controlling ' + (selected[0] ? displayName(selected[0], all.indexOf(selected[0])) : 'account');
  const live = selected.filter(i => i.online);
  const listed = total(live, i => i.telemetry?.listed);
  const slots = total(live, i => i.telemetry?.slots);
  $('hiveSlots').textContent = listed == null && slots == null ? '—' : (listed == null ? '—' : listed) + ' / ' + (slots == null ? '—' : slots);
  $('hiveBank').textContent = money(total(live, i => i.telemetry?.bank));
  $('hiveTrades').textContent = compact(total(live, i => i.telemetry?.trades));
  $('hiveOnline').textContent = online.length + ' / ' + selected.length;
  $('hiveStats').replaceChildren(...statElements(live));
  $('splitStats').replaceChildren(...statElements(all.filter(i => i.online)));
  $('hiveNote').textContent = live.length
    ? 'Hive totals · online accounts only · self-reported. Swarm ranking is not part of this self-hosted panel.'
    : 'Hive totals · no online accounts.';
  if ($('splitNote')) {
    $('splitNote').hidden = viewMode !== 'split';
    $('splitNote').textContent = live.length ? 'Hive totals · online accounts only · self-reported.' : 'Hive totals · no online accounts.';
  }
  $('hivePause').disabled = !online.length;
  $('hiveResume').disabled = !online.length;
  $('hiveRefresh').disabled = !online.length;
  $('hivePause').onclick = () => commandMany(online, 'pause');
  $('hiveResume').onclick = () => commandMany(online, 'resume');
  $('hiveRefresh').onclick = () => commandMany(online, 'snapshot');
  document.querySelectorAll('#viewToggle button').forEach(b => {
    b.setAttribute('aria-pressed', b.dataset.view === viewMode ? 'true' : 'false');
    b.onclick = () => { viewMode = b.dataset.view; localStorage.setItem('gonuts.viewMode', viewMode); if (current) render(current); };
  });
}
function render(data) {
  current = data;
  $('who').textContent = data.user.globalName || data.user.username || '';
  const all = data.installations || [];
  const cards = $('cards');
  const showCards = viewMode === 'split';
  cards.hidden = !showCards || !all.length;
  cards.replaceChildren(...(showCards ? all.map((inst, i) => card(inst, i)) : []));
  $('empty').hidden = all.length > 0;
  renderHive(data);
}
async function load() {
  try { render(await api('/dashboard/api/state', { cache: 'no-store' })); }
  catch (e) { toast(e.message, true); }
}
async function commandMany(insts, cmd) {
  const targets = insts.filter(i => i.online);
  if (!targets.length) { toast('No online accounts', true); return; }
  try {
    await Promise.all(targets.map(i => api('/dashboard/api/installations/' + i.id + '/command', {
      method: 'POST', body: JSON.stringify({ command: cmd })
    })));
    toast(cmd + ' sent to ' + targets.length + ' account' + (targets.length === 1 ? '' : 's'));
    setTimeout(load, 400);
  } catch (e) { toast(e.message, true); }
}
function command(id, cmd) {
  const inst = current && current.installations.find(i => i.id === id);
  commandMany(inst ? [inst] : [], cmd);
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
$('maskNames').onclick = () => {
  maskNames = !maskNames;
  localStorage.setItem('gonuts.mask', maskNames ? '1' : '0');
  $('maskNames').setAttribute('aria-pressed', maskNames ? 'true' : 'false');
  $('maskNames').textContent = maskNames ? 'Show names' : 'Hide names';
  if (current) render(current);
};
$('maskNames').setAttribute('aria-pressed', maskNames ? 'true' : 'false');
$('maskNames').textContent = maskNames ? 'Show names' : 'Hide names';
$('scope').addEventListener('change', e => { scope = e.target.value; localStorage.setItem('gonuts.scope', scope); if (current) render(current); });
$('linkClient').onclick = linkClient;
$('closeModal').onclick = () => { $('modal').hidden = true; load(); };
$('copyCode').onclick = async () => { try { await navigator.clipboard.writeText($('code').textContent); toast('Copied'); } catch (e) { toast('Copy failed', true); } };

// Keep same-origin navigation inside the installed app window instead of
// handing it to Safari. External links keep their default behaviour.
document.addEventListener('click', e => {
  const a = e.target.closest && e.target.closest('a[href]');
  if (!a) return;
  const url = new URL(a.href, location.href);
  if (url.origin !== location.origin) return;
  if (!a.target || a.target === '_self') return;
  e.preventDefault();
  location.href = url.href;
});

// Refresh data in place (no full reload) when the browser chrome is hidden on
// the iPhone home screen.
const refreshFab = $('refreshFab');
if (refreshFab) refreshFab.onclick = async () => {
  refreshFab.setAttribute('aria-busy', 'true');
  try { await load(); toast('Refreshed'); } finally { refreshFab.removeAttribute('aria-busy'); }
};

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
