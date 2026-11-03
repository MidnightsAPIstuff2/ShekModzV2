/* standy.best themes (black & grey by default, plus the seasonal ones). The admin picks one; the server stores it; everyone sees it. */
(function () {
  'use strict';

  var THEMES = {
    default: {
      label: 'Standy', icon: '⚫',
      vars: { '--accent': '#e4e4e7', '--accent-rgb': '228 228 231', '--accent-mid': '#a1a1aa', '--accent-dark': '#52525b', '--soft-rgb': '212 212 216', '--bg': '#050506', '--bg2': '#0a0a0b' },
      fx: null
    },
    summer: {
      label: 'Summer', icon: '☀️',
      vars: { '--accent': '#22ff66', '--accent-rgb': '34 255 102', '--accent-mid': '#14a83c', '--accent-dark': '#0b5a20', '--soft-rgb': '187 247 208', '--bg': '#010502', '--bg2': '#020a04' },
      fx: null
    },
    fall: {
      label: 'Fall', icon: '🎃',
      vars: { '--accent': '#ff7a18', '--accent-rgb': '255 122 24', '--accent-mid': '#c2570c', '--accent-dark': '#6b2e05', '--soft-rgb': '253 186 116', '--bg': '#0a0400', '--bg2': '#120600' },
      fx: {
        fall: ['🍂', '🍁', '🍂', '🍁', '🍂'], count: 26,
        bg: ['🎃', '🍁', '🎃', '🦇', '🎃', '👻'],
        row: ['🎃', '🎃', '👻', '🎃', '🍂', '🎃', '🦇', '🎃', '🍁', '🎃', '👻', '🎃', '🎃', '🍂']
      }
    },
    winter: {
      label: 'Winter', icon: '❄️',
      vars: { '--accent': '#7dd3fc', '--accent-rgb': '125 211 252', '--accent-mid': '#38a3d6', '--accent-dark': '#0c4a6e', '--soft-rgb': '186 230 253', '--bg': '#01060b', '--bg2': '#020a12' },
      fx: {
        fall: ['❄', '❅', '❆', '❄', '•'], count: 40,
        bg: ['⛄', '❄', '🎄', '❄'],
        row: ['⛄', '🎄', '❄', '🎄', '⛄', '❄', '🎄', '⛄', '❄', '🎄', '⛄', '🎄']
      }
    },
    spring: {
      label: 'Spring', icon: '🌸',
      vars: { '--accent': '#ff8fc8', '--accent-rgb': '255 143 200', '--accent-mid': '#d6589a', '--accent-dark': '#7a2a54', '--soft-rgb': '252 205 230', '--bg': '#0a0208', '--bg2': '#10030f' },
      fx: {
        fall: ['🌸', '🌸', '🌺', '🌷', '🌸'], count: 24,
        bg: ['🌷', '🦋', '🌼', '🌸'],
        row: ['🌷', '🌼', '🌷', '🦋', '🌸', '🌷', '🌼', '🌷', '🌺', '🌷', '🌼', '🌷']
      }
    }
  };

  var DEFAULT = 'default';
  var KEY = 'shek_theme';
  var root = document.documentElement;
  var current = null;
  var fxBack = null, fxFront = null;

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  function readStored() {
    try { var t = localStorage.getItem(KEY); return THEMES[t] ? t : DEFAULT; } catch (e) { return DEFAULT; }
  }
  function store(t) { try { localStorage.setItem(KEY, t); } catch (e) {} }

  function injectStyle() {
    if (document.getElementById('shekFxStyle')) return;
    var st = document.createElement('style');
    st.id = 'shekFxStyle';
    st.textContent =
      '.shek-layer{position:fixed;inset:0;pointer-events:none;overflow:hidden}' +
      '#shekFxBack{z-index:5}#shekFxFront{z-index:30}' +
      '.shek-fall{position:absolute;top:-8vh;will-change:transform;animation:shekFall linear infinite}' +
      '.shek-sway{display:block;animation:shekSway ease-in-out infinite alternate}' +
      '.shek-layer[data-theme="winter"] .shek-sway{color:rgb(var(--soft-rgb));text-shadow:0 0 8px rgba(var(--accent-rgb)/.8)}' +
      '@keyframes shekFall{from{transform:translate3d(0,-8vh,0) rotate(0deg)}to{transform:translate3d(var(--drift),112vh,0) rotate(var(--spin))}}' +
      '@keyframes shekSway{from{transform:translateX(-26px)}to{transform:translateX(26px)}}' +
      '.shek-deco{position:absolute;opacity:.10;animation:shekBob ease-in-out infinite alternate}' +
      '@keyframes shekBob{from{transform:translateY(0) rotate(-7deg)}to{transform:translateY(-18px) rotate(7deg)}}' +
      '.shek-row{position:absolute;left:0;right:0;bottom:-12px;display:flex;justify-content:space-around;align-items:flex-end}' +
      '.shek-row span{display:block;line-height:1;filter:drop-shadow(0 0 10px rgba(var(--accent-rgb)/.6));animation:shekGlow 3.5s ease-in-out infinite alternate}' +
      '@keyframes shekGlow{from{filter:drop-shadow(0 0 6px rgba(var(--accent-rgb)/.35))}to{filter:drop-shadow(0 0 16px rgba(var(--accent-rgb)/.85))}}' +
      '@media (prefers-reduced-motion:reduce){.shek-fall{display:none}.shek-deco,.shek-row span{animation:none}}';
    document.head.appendChild(st);
  }

  function buildFx() {
    if (!document.body) return;
    injectStyle();
    [fxBack, fxFront].forEach(function (el) { if (el && el.parentNode) el.parentNode.removeChild(el); });
    fxBack = fxFront = null;
    var t = THEMES[current];
    if (!t || !t.fx) return;

    // back layer sits behind the page content, front layer (leaves, snow, the pumpkin row) floats over it
    function layer(id) {
      var el = document.createElement('div');
      el.id = id;
      el.className = 'shek-layer';
      el.setAttribute('aria-hidden', 'true');
      el.setAttribute('data-theme', current);
      return el;
    }
    fxBack = layer('shekFxBack');
    fxFront = layer('shekFxFront');

    // big faint decorations floating in the background
    for (var i = 0; i < 9; i++) {
      var d = document.createElement('span');
      d.className = 'shek-deco';
      d.textContent = t.fx.bg[i % t.fx.bg.length];
      d.style.left = rnd(2, 92) + '%';
      d.style.top = rnd(6, 80) + '%';
      d.style.fontSize = rnd(60, 130) + 'px';
      d.style.animationDuration = rnd(5, 10) + 's';
      d.style.animationDelay = (-rnd(0, 8)) + 's';
      fxBack.appendChild(d);
    }

    // row along the bottom edge
    var row = document.createElement('div');
    row.className = 'shek-row';
    t.fx.row.forEach(function (g) {
      var s = document.createElement('span');
      s.textContent = g;
      s.style.fontSize = rnd(26, 50) + 'px';
      s.style.animationDelay = (-rnd(0, 4)) + 's';
      row.appendChild(s);
    });
    fxFront.appendChild(row);

    // slowly falling leaves / snow / petals
    for (var j = 0; j < t.fx.count; j++) {
      var dur = rnd(20, 38);
      var f = document.createElement('span');
      f.className = 'shek-fall';
      f.style.left = rnd(0, 100) + '%';
      f.style.fontSize = rnd(15, 32) + 'px';
      f.style.opacity = rnd(0.55, 0.95).toFixed(2);
      f.style.setProperty('--drift', rnd(-140, 140).toFixed(0) + 'px');
      f.style.setProperty('--spin', rnd(-540, 540).toFixed(0) + 'deg');
      f.style.animationDuration = dur.toFixed(1) + 's';
      f.style.animationDelay = (-rnd(0, dur)).toFixed(1) + 's';
      var inner = document.createElement('span');
      inner.className = 'shek-sway';
      inner.textContent = pick(t.fx.fall);
      inner.style.animationDuration = rnd(3, 6).toFixed(1) + 's';
      inner.style.animationDelay = (-rnd(0, 6)).toFixed(1) + 's';
      f.appendChild(inner);
      fxFront.appendChild(f);
    }

    document.body.appendChild(fxBack);
    document.body.appendChild(fxFront);
  }

  function onReady(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function apply(name, persist) {
    if (!THEMES[name]) name = DEFAULT;
    var vars = THEMES[name].vars;
    for (var k in vars) root.style.setProperty(k, vars[k]);
    root.setAttribute('data-theme', name);
    if (persist !== false) store(name);
    if (name !== current) {
      current = name;
      onReady(buildFx);
      try { document.dispatchEvent(new CustomEvent('themechange', { detail: name })); } catch (e) {}
    }
  }

  function sync() {
    fetch('/api/theme', { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && THEMES[d.theme]) apply(d.theme); })
      .catch(function () {});
  }

  window.ShekTheme = {
    themes: THEMES,
    names: Object.keys(THEMES),
    current: function () { return current; },
    rgb: function () { return THEMES[current || DEFAULT].vars['--accent-rgb'].replace(/ /g, ','); },
    apply: apply
  };

  apply(readStored(), false);   // instant, from this browser's last-seen theme (no flash)
  sync();                        // then the real site-wide theme from the server
  setInterval(sync, 60000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) sync(); });
})();
