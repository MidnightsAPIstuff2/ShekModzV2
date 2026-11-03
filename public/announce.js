/* Shek Modz announcements. The admin publishes one; the server stores it; everyone sees it.
   type "bar"   -> glowing bar pinned to the top of the screen until the admin removes it
   type "popup" -> modal the visitor has to close (stays closed for that announcement once they do) */
(function () {
  'use strict';

  var SEEN_KEY = 'shek_announce_seen';
  var POLL_MS = 60000;

  var current = { active: false };
  var dismissedId = null;          // in-memory fallback if localStorage is unavailable
  var barEl = null, barText = null, barObserver = null;
  var popEl = null, popReturnFocus = null;

  function onReady(fn) {
    if (document.body) fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  /* ---------- "seen" memory for pop-ups ---------- */
  function wasSeen(id) {
    if (dismissedId === id) return true;
    try { return localStorage.getItem(SEEN_KEY) === id; } catch (e) { return false; }
  }
  function markSeen(id) {
    dismissedId = id;
    try { localStorage.setItem(SEEN_KEY, id); } catch (e) {}
  }

  /* ---------- styles (colours come from the active theme, with green fallbacks) ---------- */
  function injectStyle() {
    if (document.getElementById('shekAnnStyle')) return;
    var A = 'var(--accent-rgb,228 228 231)';
    var S = 'var(--soft-rgb,212 212 216)';
    var css =
      /* bar */
      '.shek-ann-bar{position:fixed;top:0;left:0;right:0;z-index:45;display:flex;align-items:center;justify-content:center;gap:10px;' +
        'padding:10px 16px;text-align:center;color:#000;font:700 13px/1.45 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;letter-spacing:.04em;' +
        'background-color:rgb(' + A + ');' +
        'background-image:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.38) 50%,transparent 70%);background-size:250% 100%;' +
        'box-shadow:0 0 18px rgb(' + A + '/.85),0 0 42px rgb(' + A + '/.5);' +
        'animation:shekAnnSweep 5s linear infinite,shekAnnGlow 2.6s ease-in-out infinite alternate}' +
      '.shek-ann-bar .shek-ann-text{white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}' +
      '.shek-ann-bar .shek-ann-ico{flex:none}' +
      '@keyframes shekAnnSweep{from{background-position:130% 0}to{background-position:-130% 0}}' +
      '@keyframes shekAnnGlow{from{box-shadow:0 0 10px rgb(' + A + '/.6),0 0 24px rgb(' + A + '/.3)}to{box-shadow:0 0 22px rgb(' + A + '/.95),0 0 56px rgb(' + A + '/.6)}}' +
      /* keep the sticky header and the takedown page's Home button below the bar */
      'header.sticky{top:var(--announce-h,0px)!important}' +
      '.home{top:calc(16px + var(--announce-h,0px))!important}' +
      /* pop-up */
      '.shek-ann-overlay{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;padding:16px;' +
        'background:rgba(0,0,0,.86);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}' +
      '.shek-ann-panel{width:100%;max-width:520px;max-height:90vh;display:flex;flex-direction:column;padding:28px 24px 24px;text-align:center;' +
        'border:1px solid rgb(' + A + '/.55);border-radius:18px;background:rgba(10,10,12,.96);color:rgb(' + A + ');' +
        'font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;' +
        'box-shadow:0 0 30px rgb(' + A + '/.5),inset 0 0 18px rgb(' + A + '/.15);animation:shekAnnPop .25s ease-out}' +
      '.shek-ann-title{margin:0 0 14px;font-size:15px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;' +
        'text-shadow:0 0 12px rgb(' + A + '/.85),0 0 26px rgb(' + A + '/.45)}' +
      '.shek-ann-msg{margin:0 0 22px;overflow-y:auto;color:rgb(' + S + ');font-size:15px;line-height:1.65;white-space:pre-wrap;overflow-wrap:anywhere}' +
      '.shek-ann-close{align-self:center;padding:11px 34px;border:0;border-radius:12px;cursor:pointer;background:rgb(' + A + ');color:#000;' +
        'font:800 12px "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;' +
        'box-shadow:0 0 18px rgb(' + A + '/.65);transition:box-shadow .2s,transform .2s}' +
      '.shek-ann-close:hover,.shek-ann-close:focus-visible{outline:none;box-shadow:0 0 30px rgb(' + A + '/.95);transform:translateY(-1px)}' +
      '@keyframes shekAnnPop{from{opacity:0;transform:scale(.94) translateY(8px)}to{opacity:1;transform:none}}' +
      '@media (prefers-reduced-motion:reduce){.shek-ann-bar{animation:none}.shek-ann-panel{animation:none}}';
    var st = document.createElement('style');
    st.id = 'shekAnnStyle';
    st.textContent = css;
    document.head.appendChild(st);
  }

  /* ---------- bar ---------- */
  function setBarOffset() {
    var h = barEl ? Math.ceil(barEl.getBoundingClientRect().height) : 0;
    document.documentElement.style.setProperty('--announce-h', h + 'px');
    document.body.style.paddingTop = h ? h + 'px' : '';
  }
  function removeBar() {
    if (barObserver) { barObserver.disconnect(); barObserver = null; }
    window.removeEventListener('resize', setBarOffset);
    if (barEl && barEl.parentNode) barEl.parentNode.removeChild(barEl);
    barEl = barText = null;
    setBarOffset();
  }
  function renderBar() {
    if (!(current.active && current.type === 'bar')) { if (barEl) removeBar(); return; }
    injectStyle();
    if (!barEl) {
      barEl = document.createElement('div');
      barEl.className = 'shek-ann-bar';
      barEl.setAttribute('role', 'status');
      var ico = document.createElement('span');
      ico.className = 'shek-ann-ico';
      ico.setAttribute('aria-hidden', 'true');
      ico.textContent = '📢';
      barText = document.createElement('span');
      barText.className = 'shek-ann-text';
      barEl.appendChild(ico);
      barEl.appendChild(barText);
      document.body.insertBefore(barEl, document.body.firstChild);
      if (window.ResizeObserver) { barObserver = new ResizeObserver(setBarOffset); barObserver.observe(barEl); }
      else window.addEventListener('resize', setBarOffset);
    }
    barText.textContent = current.message;   // textContent: admin text is never parsed as HTML
    setBarOffset();
  }

  /* ---------- pop-up ---------- */
  function onPopKey(e) {
    if (!popEl) return;
    if (e.key === 'Escape') { e.preventDefault(); closePopup(true); }
    else if (e.key === 'Tab') { e.preventDefault(); var b = popEl.querySelector('button'); if (b) b.focus(); }
  }
  function removePopupDom() {
    if (!popEl) return;
    document.removeEventListener('keydown', onPopKey, true);
    if (popEl.parentNode) popEl.parentNode.removeChild(popEl);
    popEl = null;
  }
  function closePopup(remember) {
    if (!popEl) return;
    if (remember) markSeen(popEl.getAttribute('data-id'));
    removePopupDom();
    if (popReturnFocus && popReturnFocus.focus) { try { popReturnFocus.focus(); } catch (e) {} }
    popReturnFocus = null;
  }
  function renderPopup() {
    var want = current.active && current.type === 'popup' && !wasSeen(current.id);
    if (!want) { removePopupDom(); return; }
    if (popEl && popEl.getAttribute('data-id') === current.id) return;   // already showing this one
    removePopupDom();
    injectStyle();

    if (!popReturnFocus) popReturnFocus = document.activeElement;
    popEl = document.createElement('div');
    popEl.className = 'shek-ann-overlay';
    popEl.setAttribute('data-id', current.id);

    var panel = document.createElement('div');
    panel.className = 'shek-ann-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-labelledby', 'shekAnnTitle');

    var title = document.createElement('h2');
    title.className = 'shek-ann-title';
    title.id = 'shekAnnTitle';
    title.textContent = '📢 Announcement';

    var msg = document.createElement('p');
    msg.className = 'shek-ann-msg';
    msg.textContent = current.message;       // textContent: never parsed as HTML

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'shek-ann-close';
    btn.textContent = 'Close';
    btn.addEventListener('click', function () { closePopup(true); });

    panel.appendChild(title);
    panel.appendChild(msg);
    panel.appendChild(btn);
    popEl.appendChild(panel);
    document.body.appendChild(popEl);
    document.addEventListener('keydown', onPopKey, true);
    btn.focus();
  }

  /* ---------- state ---------- */
  function apply(a) {
    current = a && a.active && a.message ? a : { active: false };
    onReady(function () { renderBar(); renderPopup(); });
  }

  function sync() {
    return fetch('/api/announcement', { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) apply(d); })
      .catch(function () {});
  }

  window.ShekAnnounce = {
    apply: apply,
    refresh: sync,
    current: function () { return current; }
  };

  sync();
  setInterval(sync, POLL_MS);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) sync(); });
})();
