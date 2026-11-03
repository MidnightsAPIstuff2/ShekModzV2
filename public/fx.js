/* standy.best background + glare.
 * 1) A network of floating dots joined by lines. The mouse pushes them away. Colour follows the site theme.
 * 2) A light "glare" that follows the mouse over panels and buttons (works with /shine.css). */
(function () {
  'use strict';
  if (window.__standyFx) return;
  window.__standyFx = true;

  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var rgb = '228,228,231';
  function readRgb() {
    try {
      var v = getComputedStyle(document.documentElement).getPropertyValue('--accent-rgb').trim();
      if (v) rgb = v.split(/[\s,]+/).slice(0, 3).join(',');
    } catch (e) {}
  }

  function network() {
    var cv = document.createElement('canvas');
    cv.id = 'netBg';
    cv.setAttribute('aria-hidden', 'true');
    cv.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none';
    document.body.insertBefore(cv, document.body.firstChild);
    var ctx = cv.getContext('2d');
    var W = 0, H = 0, dpr = 1, dots = [], LINK = 140, PUSH = 150;
    var mouse = { x: -9999, y: -9999, on: false };
    var raf = 0;

    function rnd(a, b) { return a + Math.random() * (b - a); }
    function make() {
      var n = Math.max(36, Math.min(130, Math.round(W * H / 12000)));
      if (W < 700) n = Math.min(n, 55);
      dots.length = 0;
      for (var i = 0; i < n; i++) {
        var a = Math.random() * Math.PI * 2, sp = rnd(0.12, 0.42);
        dots.push({ x: rnd(0, W), y: rnd(0, H), bx: Math.cos(a) * sp, by: Math.sin(a) * sp, vx: 0, vy: 0, r: rnd(1, 2.3) });
        dots[i].vx = dots[i].bx; dots[i].vy = dots[i].by;
      }
    }
    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = window.innerWidth; H = window.innerHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      make();
      if (reduce) frame();
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);
      var i, j, d, dx, dy, dist, f;
      for (i = 0; i < dots.length; i++) {
        d = dots[i];
        if (!reduce) {
          if (mouse.on) {
            dx = d.x - mouse.x; dy = d.y - mouse.y; dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < PUSH && dist > 0.01) {
              f = Math.pow(1 - dist / PUSH, 2) * 2.6;
              d.vx += (dx / dist) * f; d.vy += (dy / dist) * f;
            }
          }
          d.vx += (d.bx - d.vx) * 0.035; d.vy += (d.by - d.vy) * 0.035;      // ease back to the lazy drift
          d.x += d.vx; d.y += d.vy;
          if (d.x < -20) d.x = W + 20; else if (d.x > W + 20) d.x = -20;
          if (d.y < -20) d.y = H + 20; else if (d.y > H + 20) d.y = -20;
        }
      }
      ctx.lineWidth = 1;
      for (i = 0; i < dots.length; i++) {
        d = dots[i];
        for (j = i + 1; j < dots.length; j++) {
          dx = d.x - dots[j].x; if (dx > LINK || dx < -LINK) continue;
          dy = d.y - dots[j].y; if (dy > LINK || dy < -LINK) continue;
          dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < LINK) {
            ctx.strokeStyle = 'rgba(' + rgb + ',' + ((1 - dist / LINK) * 0.38).toFixed(3) + ')';
            ctx.beginPath(); ctx.moveTo(d.x, d.y); ctx.lineTo(dots[j].x, dots[j].y); ctx.stroke();
          }
        }
        if (mouse.on) {                                                       // faint lines out to the cursor
          dx = d.x - mouse.x; dy = d.y - mouse.y; dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < LINK + 40) {
            ctx.strokeStyle = 'rgba(' + rgb + ',' + ((1 - dist / (LINK + 40)) * 0.3).toFixed(3) + ')';
            ctx.beginPath(); ctx.moveTo(d.x, d.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
          }
        }
      }
      ctx.fillStyle = 'rgba(' + rgb + ',0.85)';
      for (i = 0; i < dots.length; i++) { d = dots[i]; ctx.beginPath(); ctx.arc(d.x, d.y, d.r, 0, 6.2832); ctx.fill(); }
      if (!reduce) raf = requestAnimationFrame(frame);
    }

    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', function (e) { mouse.x = e.clientX; mouse.y = e.clientY; mouse.on = true; }, { passive: true });
    document.documentElement.addEventListener('pointerleave', function () { mouse.on = false; });
    window.addEventListener('blur', function () { mouse.on = false; });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) cancelAnimationFrame(raf); else if (!reduce) { cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }
    });
    document.addEventListener('themechange', function () { readRgb(); if (reduce) frame(); });
    resize();
    if (!reduce) raf = requestAnimationFrame(frame);
  }

  /* glare that follows the pointer across panels / buttons */
  var GLARE = '.glass-panel,.glow-box-sm,.glow-heavy,.card,.btn,.home,.shine,button[class*="rounded"],a[class*="rounded"]';
  var pend = null, glareEl = null;
  function glare() {
    pend = null;
    if (!glareEl) return;
    var r = glareEl.getBoundingClientRect();
    glareEl.style.setProperty('--gx', Math.round(pend_x - r.left) + 'px');
    glareEl.style.setProperty('--gy', Math.round(pend_y - r.top) + 'px');
  }
  var pend_x = 0, pend_y = 0;
  window.addEventListener('pointermove', function (e) {
    if (e.pointerType === 'touch') return;
    var t = e.target && e.target.closest ? e.target.closest(GLARE) : null;
    if (!t) return;
    glareEl = t; pend_x = e.clientX; pend_y = e.clientY;
    if (!pend) pend = requestAnimationFrame(glare);
  }, { passive: true });

  /* shimmer sweep: plays when the pointer arrives, then that element rests for 5 seconds */
  var COOLDOWN = 5000;
  document.addEventListener('pointerover', function (e) {
    if (e.pointerType === 'touch' || reduce) return;
    var t = e.target && e.target.closest ? e.target.closest(GLARE) : null;
    if (!t) return;
    var now = Date.now();
    if (now - (t.__sweptAt || 0) < COOLDOWN) return;
    t.__sweptAt = now;
    t.classList.add('sweeping');
    setTimeout(function () { t.classList.remove('sweeping'); }, 950);
  }, { passive: true });

  function boot() { readRgb(); network(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
