/* Proximity dock physics from ThreeUI <AnimatedTopDock /> (MIT,
 @designcodeio/threeui 1.2.0, src/shaders/animated-top-dock/topDockController.ts).
 Copied verbatim from the published build; see licenses/threeui-LICENSE.
 Any element inside the nav with [data-dock-item] grows toward the pointer;
 it turns itself off for reduced motion, touch and viewports under 600px. */

const y = (n, r, h) => Math.max(r, Math.min(h, n));
function N(n, r) {
  const h = window.matchMedia("(prefers-reduced-motion: reduce)"), p = window.matchMedia("(hover:hover) and (pointer:fine)"), c = Array.from(n.querySelectorAll("[data-dock-item]")).map((e) => ({
    element: e,
    baseWidth: 0,
    baseHeight: 0,
    value: 0,
    velocity: 0,
    target: 0
  }));
  let u = !1, f = !1, m = !1, w = 0;
  const G = () => !h.matches && n.clientWidth > 0 && window.innerWidth > 600 && p.matches, l = () => {
    u = G(), r().lockTrack && (n.style.width = "");
    for (const e of c)
      e.element.style.width = "", e.element.style.height = "", e.element.style.transform = "", e.element.dataset.dockNear = "false";
    for (const e of c) {
      const t = e.element.getBoundingClientRect();
      e.baseWidth = t.width, e.baseHeight = t.height, e.value = 0, e.velocity = 0, e.target = 0;
    }
    f = !1, m = !1, r().distribute && k(), r().lockTrack && (n.style.width = `${n.getBoundingClientRect().width.toFixed(2)}px`), n.dataset.dockState = u ? "idle" : "static", n.dataset.dockMax = "0.00";
  }, B = (e, t) => {
    if (!u) return;
    const a = r(), i = a.axis === "y", d = i ? t : e, s = c.map((o) => o.element.getBoundingClientRect());
    for (let o = 0; o < c.length; o += 1) {
      const g = s[o], q = i ? g.top + g.height * 0.5 : g.left + g.width * 0.5, x = y(1 - Math.abs(d - q) / Math.max(1, a.proximity), 0, 1), $ = x * x * (3 - 2 * x);
      c[o].target = $, c[o].element.dataset.dockNear = $ > 0.08 ? "true" : "false";
    }
    f = !0, m = !0, n.dataset.dockState = "active";
  }, H = (e) => {
    if (!u) return;
    const t = c.findIndex((a) => a.element === e);
    t < 0 || (c.forEach((a, i) => {
      a.target = i === t ? 1 : Math.abs(i - t) === 1 ? 0.24 : 0, a.element.dataset.dockNear = a.target > 0.08 ? "true" : "false";
    }), f = !1, m = !0, n.dataset.dockState = "focus");
  }, v = () => {
    f = !1, m = !0, c.forEach((e) => {
      e.target = 0, e.element.dataset.dockNear = "false";
    });
  }, k = () => {
    const e = r();
    if (e.distribute && e.axis !== "y") {
      const t = c.map((s) => s.baseWidth + e.widthGrowth * y(s.value, 0, 1.08)), a = t.reduce((s, o) => s + o, 0), i = c.reduce((s, o) => s + o.baseWidth, 0), d = n.clientWidth >= i ? n.clientWidth : 0;
      c.forEach((s, o) => {
        s.element.style.width = d ? `${(d * t[o] / a).toFixed(2)}px` : "", s.element.style.height = "", s.element.style.transform = "";
      });
      return;
    }
    for (const t of c) {
      const a = y(t.value, 0, 1.08);
      if (e.axis === "y") {
        t.element.style.width = "", t.element.style.height = `${(t.baseHeight + e.heightGrowth * a).toFixed(2)}px`, t.element.style.transform = `translateX(${(a * e.drop).toFixed(2)}px)`;
        continue;
      }
      const i = t.element.classList.contains("animated-top-dock__logo"), d = i ? e.widthGrowth * (14 / 17) : Math.min(e.widthGrowth, t.baseWidth * 0.24), s = i ? e.heightGrowth * (14 / 16) : e.heightGrowth;
      t.element.style.width = `${(t.baseWidth + d * a).toFixed(2)}px`, t.element.style.height = `${(t.baseHeight + s * a).toFixed(2)}px`, t.element.style.transform = `translateY(${(a * e.drop).toFixed(2)}px)`;
    }
  }, E = () => {
    if (u && m) {
      const e = r();
      let t = !1, a = 0;
      for (const i of c)
        i.velocity += (i.target - i.value) * e.spring, i.velocity *= e.damping, i.value += i.velocity, Math.abs(i.target - i.value) < 1e-3 && Math.abs(i.velocity) < 1e-3 ? (i.value = i.target, i.velocity = 0) : t = !0, a = Math.max(a, y(i.value, 0, 1.08));
      k(), n.dataset.dockMax = a.toFixed(2), t || (m = !1, c.every((i) => i.target === 0) && (n.dataset.dockState = "idle"));
    }
    w = requestAnimationFrame(E);
  }, b = (e) => B(e.clientX, e.clientY), L = (e) => {
    if (!f) return;
    const t = n.getBoundingClientRect(), a = c.map((s) => s.element.getBoundingClientRect()), i = Math.max(t.bottom, ...a.map((s) => s.bottom));
    (e.clientX < t.left || e.clientX > t.right || e.clientY < t.top || e.clientY > i) && v();
  }, M = (e) => {
    const t = e.target?.closest("[data-dock-item]");
    t && H(t);
  }, F = () => requestAnimationFrame(() => {
    n.contains(document.activeElement) || v();
  }), W = (e) => {
    const t = e.target?.closest("[data-dock-item]");
    t && (e.key === "Enter" || e.key === " ") && (e.preventDefault(), t.click());
  }, A = () => v();
  let R = !1;
  const S = () => {
    R || l();
  };
  document.fonts?.ready.then(S);
  const C = new ResizeObserver(l);
  return C.observe(n.closest("[data-dock-frame]") ?? n.parentElement ?? n), n.addEventListener("pointermove", b), n.addEventListener("pointerleave", v), n.addEventListener("focusin", M), n.addEventListener("focusout", F), n.addEventListener("keydown", W), n.addEventListener("click", A), window.addEventListener("pointermove", L, { passive: !0 }), h.addEventListener("change", l), p.addEventListener("change", l), l(), w = requestAnimationFrame(E), () => {
    R = !0, n.style.width = "", cancelAnimationFrame(w), C.disconnect(), n.removeEventListener("pointermove", b), n.removeEventListener("pointerleave", v), n.removeEventListener("focusin", M), n.removeEventListener("focusout", F), n.removeEventListener("keydown", W), n.removeEventListener("click", A), window.removeEventListener("pointermove", L), h.removeEventListener("change", l), p.removeEventListener("change", l);
  };
}
export {
  N as createTopDockController
};
