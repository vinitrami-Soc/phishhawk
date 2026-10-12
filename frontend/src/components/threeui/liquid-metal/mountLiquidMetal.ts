/* The liquid metal renderer from ThreeUI (MIT, @designcodeio/threeui 1.2.0,
   liquid-metal-button.html), moved out of its srcdoc iframe so it runs under
   PhishHawk's Content-Security-Policy (no inline script, no inline style).

   The render passes, the easing constants and the interaction model are the
   original's, line for line. What changed, and only this:
   - it draws into a canvas behind a real <button> in the page, instead of a
     button inside an iframe that talks to the page with postMessage;
   - body.hot / body.press became classes on the component's root element;
   - every listener, observer, frame and GL object is released by dispose();
   - no window.__ tuning hooks, and no innerHTML fallback (the caller shows a
     CSS fallback when this returns null). */

import {
  DEFAULT_C,
  DEFAULT_E,
  DEFAULT_P,
  DEFAULT_R,
  FRAG_BLUR,
  FRAG_COMP,
  FRAG_DOWN,
  FRAG_RIM,
  FRAG_SCENE,
  VERT,
} from './shaders';

export type LiquidMetalElements = {
  root: HTMLElement;
  stage: HTMLElement;
  canvas: HTMLCanvasElement;
  button: HTMLButtonElement;
};

type Target = { tex: WebGLTexture; fbo: WebGLFramebuffer; w: number; h: number };
type Program = { p: WebGLProgram; u: Record<string, WebGLUniformLocation | null> };

export function mountLiquidMetal(
  { root, stage, canvas: cv, button: btn }: LiquidMetalElements,
  onContextLost?: () => void,
): (() => void) | null {
  const gl = cv.getContext('webgl2', {
    alpha: true,
    antialias: false,
    premultipliedAlpha: true,
    powerPreference: 'high-performance',
  });
  if (!gl) return null;

  const P: Record<string, number> = { ...DEFAULT_P };
  const PKEYS = Object.keys(P);
  const E: Record<string, number> = { ...DEFAULT_E };
  const EKEYS = Object.keys(E);
  const C = { ...DEFAULT_C };
  const R = { ...DEFAULT_R };

  const shaders: WebGLShader[] = [];
  function sh(type: number, src: string) {
    const s = gl!.createShader(type)!;
    gl!.shaderSource(s, src);
    gl!.compileShader(s);
    if (!gl!.getShaderParameter(s, gl!.COMPILE_STATUS)) throw new Error(gl!.getShaderInfoLog(s) + '\n' + src);
    shaders.push(s);
    return s;
  }
  const programs: WebGLProgram[] = [];
  function prog(fs: string): Program {
    const p = gl!.createProgram()!;
    gl!.attachShader(p, sh(gl!.VERTEX_SHADER, VERT));
    gl!.attachShader(p, sh(gl!.FRAGMENT_SHADER, fs));
    gl!.bindAttribLocation(p, 0, 'position');
    gl!.linkProgram(p);
    if (!gl!.getProgramParameter(p, gl!.LINK_STATUS)) throw new Error(gl!.getProgramInfoLog(p) ?? 'link failed');
    const u: Program['u'] = {};
    const n = gl!.getProgramParameter(p, gl!.ACTIVE_UNIFORMS) as number;
    for (let i = 0; i < n; i++) {
      const info = gl!.getActiveUniform(p, i)!;
      u[info.name.replace('[0]', '')] = gl!.getUniformLocation(p, info.name);
    }
    programs.push(p);
    return { p, u };
  }
  const pScene = prog(FRAG_SCENE),
    pRim = prog(FRAG_RIM),
    pDown = prog(FRAG_DOWN),
    pBlur = prog(FRAG_BLUR),
    pComp = prog(FRAG_COMP);

  const vao = gl.createVertexArray();
  gl.bindVertexArray(vao);
  const vbo = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

  const hasFloat = !!gl.getExtension('EXT_color_buffer_half_float');
  const targets: Target[] = [];
  function makeTarget(): Target {
    const tex = gl!.createTexture()!;
    gl!.bindTexture(gl!.TEXTURE_2D, tex);
    gl!.texParameteri(gl!.TEXTURE_2D, gl!.TEXTURE_MIN_FILTER, gl!.LINEAR);
    gl!.texParameteri(gl!.TEXTURE_2D, gl!.TEXTURE_MAG_FILTER, gl!.LINEAR);
    gl!.texParameteri(gl!.TEXTURE_2D, gl!.TEXTURE_WRAP_S, gl!.CLAMP_TO_EDGE);
    gl!.texParameteri(gl!.TEXTURE_2D, gl!.TEXTURE_WRAP_T, gl!.CLAMP_TO_EDGE);
    const fbo = gl!.createFramebuffer()!;
    gl!.bindFramebuffer(gl!.FRAMEBUFFER, fbo);
    gl!.framebufferTexture2D(gl!.FRAMEBUFFER, gl!.COLOR_ATTACHMENT0, gl!.TEXTURE_2D, tex, 0);
    const t = { tex, fbo, w: 0, h: 0 };
    targets.push(t);
    return t;
  }
  function sizeTarget(t: Target, w: number, h: number) {
    if (t.w === w && t.h === h) return;
    t.w = w;
    t.h = h;
    gl!.bindTexture(gl!.TEXTURE_2D, t.tex);
    if (hasFloat) gl!.texImage2D(gl!.TEXTURE_2D, 0, gl!.RGBA16F, w, h, 0, gl!.RGBA, gl!.HALF_FLOAT, null);
    else gl!.texImage2D(gl!.TEXTURE_2D, 0, gl!.RGBA8, w, h, 0, gl!.RGBA, gl!.UNSIGNED_BYTE, null);
  }
  const T_core = makeTarget(),
    T_rim = makeTarget(),
    T_s1 = makeTarget(),
    T_s2 = makeTarget(),
    T_a = makeTarget(),
    T_b = makeTarget();

  let W = 0,
    H = 0,
    DPR = 1,
    BW = 0,
    BH = 0,
    CX = 0,
    CY = 0;
  let DOWN = 4;
  const GLOW_TEX = 129;
  let needResize = true;

  function resize() {
    const r = stage.getBoundingClientRect();
    const br = btn.getBoundingClientRect();
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.max(2, Math.round(r.width * DPR));
    const h = Math.max(2, Math.round(r.height * DPR));
    if (w !== W || h !== H) {
      W = w;
      H = h;
      cv.width = W;
      cv.height = H;
    }
    BW = br.width * DPR;
    BH = br.height * DPR;
    CX = (br.left - r.left) * DPR + BW / 2;
    CY = H - ((br.top - r.top) * DPR + BH / 2);
    sizeTarget(T_core, W, H);
    sizeTarget(T_rim, W, H);
    const hw = Math.max(2, Math.ceil(W / 2)),
      hh = Math.max(2, Math.ceil(H / 2));
    sizeTarget(T_s1, hw, hh);
    sizeTarget(T_s2, hw, hh);
    DOWN = Math.max(1, Math.min(4, Math.round(BH / GLOW_TEX)));
    const dw = Math.max(2, Math.ceil(W / DOWN)),
      dh = Math.max(2, Math.ceil(H / DOWN));
    sizeTarget(T_a, dw, dh);
    sizeTarget(T_b, dw, dh);
    needResize = false;
  }
  const resizeObserver = new ResizeObserver(() => {
    needResize = true;
  });
  resizeObserver.observe(stage);

  function drawTo(t: Target | null) {
    gl!.bindFramebuffer(gl!.FRAMEBUFFER, t ? t.fbo : null);
    gl!.viewport(0, 0, t ? t.w : W, t ? t.h : H);
    gl!.drawArrays(gl!.TRIANGLES, 0, 3);
  }

  const uArr = new Float32Array(PKEYS.length);
  const eArr = new Float32Array(EKEYS.length);
  let hover = 0,
    hoverTarget = 0,
    clock = 0,
    last = performance.now();

  const RIP = [0, 1, 2].map(() => ({ x: 0, y: 0, t: -99, on: 0 }));
  const ripArr = new Float32Array(12);
  let ripNext = 0,
    press = 0,
    pressTarget = 0;

  const ptr = { x: 0, y: 0 },
    ptrS = { x: 0, y: 0 };
  let ptrAmt = 0,
    ptrSpeed = 0;

  function addRipple(x: number, y: number) {
    const r = RIP[ripNext];
    ripNext = (ripNext + 1) % RIP.length;
    r.x = x;
    r.y = y;
    r.t = clock;
    r.on = 1;
  }
  function localPt(e: PointerEvent): [number, number] {
    const b = btn.getBoundingClientRect(),
      s = b.height;
    return [(e.clientX - (b.left + b.width / 2)) / s, (e.clientY - (b.top + b.height / 2)) / s];
  }

  const calm = matchMedia('(prefers-reduced-motion: reduce)');
  let drawn: string | null = null;
  let raf = 0;

  const on = { over: false, press: false, focus: false };
  const sync = () => {
    hoverTarget = on.over || on.press || on.focus ? 1 : 0;
    pressTarget = on.press ? 1 : 0;
    root.classList.toggle('is-hot', hoverTarget > 0.5);
    root.classList.toggle('is-press', on.press);
  };

  function frame(now: number) {
    const dtRaw = (now - last) / 1000;
    last = now;
    const dt = Math.min(dtRaw, 1 / 20);
    if (!calm.matches) clock += dt;

    const k = hoverTarget > hover ? 1 - Math.pow(0.0012, dt) : 1 - Math.pow(0.00012, dt);
    hover += (hoverTarget - hover) * k;
    if (Math.abs(hoverTarget - hover) < 0.0008) hover = hoverTarget;

    const pk = pressTarget > press ? 1 - Math.pow(1e-9, dt) : 1 - Math.pow(0.004, dt);
    press += (pressTarget - press) * pk;
    if (Math.abs(pressTarget - press) < 0.002) press = pressTarget;

    for (let i = 0; i < RIP.length; i++) {
      const r = RIP[i];
      if (r.on && clock - r.t > 4) r.on = 0;
      ripArr[i * 4] = r.x;
      ripArr[i * 4 + 1] = r.y;
      ripArr[i * 4 + 2] = r.t;
      ripArr[i * 4 + 3] = r.on;
    }
    const ripLive = RIP.some((r) => r.on);

    const lag = 1 - Math.pow(R.ptrLag, dt);
    const dx = (ptr.x - ptrS.x) * lag,
      dy = (ptr.y - ptrS.y) * lag;
    ptrS.x += dx;
    ptrS.y += dy;
    const inst = Math.min(Math.hypot(dx, dy) / Math.max(dt, 1e-3) / R.ptrVref, 1);
    ptrSpeed += (inst - ptrSpeed) * (1 - Math.pow(inst > ptrSpeed ? 0.001 : 0.02, dt));
    const wantWell = on.over || on.press ? 1 : 0;
    ptrAmt += (wantWell - ptrAmt) * (1 - Math.pow(0.004, dt));
    if (Math.abs(wantWell - ptrAmt) < 0.002) ptrAmt = wantWell;

    if (needResize) resize();

    const sig = calm.matches && !ripLive && ptrAmt < 0.002 ? `${hover}|${press}|${W}|${H}` : null;
    if (sig !== null && sig === drawn) {
      raf = requestAnimationFrame(frame);
      return;
    }
    drawn = sig;

    for (let i = 0; i < uArr.length; i++) uArr[i] = P[PKEYS[i]];
    for (let i = 0; i < eArr.length; i++) eArr[i] = E[EKEYS[i]];
    const bw = Math.max(1.5, 3.2 * (BH / 516));

    gl!.useProgram(pScene.p);
    gl!.uniform2f(pScene.u.uC, CX, CY);
    gl!.uniform2f(pScene.u.uHalf, BW / 2, BH / 2);
    gl!.uniform1f(pScene.u.uT, clock);
    gl!.uniform1f(pScene.u.uHover, hover);
    gl!.uniform1f(pScene.u.uPress, press);
    gl!.uniform4fv(pScene.u.uRip, ripArr);
    gl!.uniform4f(pScene.u.uRipK, R.speed, R.width, R.decay, R.amp);
    gl!.uniform4f(pScene.u.uRipK2, R.facet, R.lobes, R.sharp, R.emit);
    gl!.uniform4f(pScene.u.uPtr, ptrS.x, ptrS.y, ptrAmt, ptrSpeed);
    gl!.uniform4f(pScene.u.uPtrK, R.ptrRad, R.ptrAmp, R.ptrFast, R.ptrRim);
    gl!.uniform1fv(pScene.u.uP, uArr);
    drawTo(T_core);

    gl!.useProgram(pRim.p);
    gl!.uniform2f(pRim.u.uC, CX, CY);
    gl!.uniform2f(pRim.u.uHalf, BW / 2, BH / 2);
    gl!.uniform1f(pRim.u.uT, clock);
    gl!.uniform1f(pRim.u.uBw, bw);
    gl!.uniform1f(pRim.u.uPress, press);
    gl!.uniform4fv(pRim.u.uRip, ripArr);
    gl!.uniform4f(pRim.u.uRipK, R.speed, R.width, R.decay, R.amp);
    gl!.uniform4f(pRim.u.uRipK2, R.facet, R.lobes, R.sharp, R.emit);
    gl!.uniform4f(pRim.u.uPtr, ptrS.x, ptrS.y, ptrAmt, ptrSpeed);
    gl!.uniform4f(pRim.u.uPtrK, R.ptrRad, R.ptrAmp, R.ptrFast, R.ptrRim);
    gl!.uniform1fv(pRim.u.uE, eArr);
    drawTo(T_rim);

    gl!.useProgram(pDown.p);
    gl!.activeTexture(gl!.TEXTURE0);
    gl!.bindTexture(gl!.TEXTURE_2D, T_core.tex);
    gl!.uniform1i(pDown.u.uTex, 0);
    gl!.uniform1f(pDown.u.uAdd, 0);
    gl!.uniform2f(pDown.u.uDstTexel, 1 / T_s1.w, 1 / T_s1.h);
    gl!.uniform2f(pDown.u.uSrcTexel, 1 / W, 1 / H);
    drawTo(T_s1);

    gl!.useProgram(pBlur.p);
    gl!.uniform1i(pBlur.u.uTex, 0);
    gl!.uniform2f(pBlur.u.uTexel, 1 / T_s1.w, 1 / T_s1.h);
    const sigTex = C.soften * (BH * 0.5) * 0.95;
    if (sigTex > 0.1) {
      const iters = Math.min(4, Math.max(1, Math.ceil(sigTex / 3.0)));
      gl!.uniform1f(pBlur.u.uR, sigTex / Math.sqrt(iters) / 1.95);
      for (let i = 0; i < iters; i++) {
        gl!.bindTexture(gl!.TEXTURE_2D, T_s1.tex);
        gl!.uniform2f(pBlur.u.uDir, 1, 0);
        drawTo(T_s2);
        gl!.bindTexture(gl!.TEXTURE_2D, T_s2.tex);
        gl!.uniform2f(pBlur.u.uDir, 0, 1);
        drawTo(T_s1);
      }
    }

    gl!.useProgram(pDown.p);
    gl!.activeTexture(gl!.TEXTURE0);
    gl!.bindTexture(gl!.TEXTURE_2D, T_s1.tex);
    gl!.activeTexture(gl!.TEXTURE1);
    gl!.bindTexture(gl!.TEXTURE_2D, T_rim.tex);
    gl!.uniform1i(pDown.u.uTex, 0);
    gl!.uniform1i(pDown.u.uTex2, 1);
    gl!.uniform1f(pDown.u.uAdd, 1);
    gl!.uniform2f(pDown.u.uDstTexel, 1 / T_a.w, 1 / T_a.h);
    gl!.uniform2f(pDown.u.uSrcTexel, 1 / T_s1.w, 1 / T_s1.h);
    drawTo(T_a);

    gl!.useProgram(pBlur.p);
    gl!.activeTexture(gl!.TEXTURE0);
    gl!.uniform1i(pBlur.u.uTex, 0);
    gl!.uniform2f(pBlur.u.uTexel, 1 / T_a.w, 1 / T_a.h);
    const rs = (C.glowR * (BH / DOWN)) / GLOW_TEX;
    for (const r of [1.0, 2.3, 5.2, 9.0].map((v) => v * rs)) {
      gl!.uniform1f(pBlur.u.uR, r);
      gl!.bindTexture(gl!.TEXTURE_2D, T_a.tex);
      gl!.uniform2f(pBlur.u.uDir, 1, 0);
      drawTo(T_b);
      gl!.bindTexture(gl!.TEXTURE_2D, T_b.tex);
      gl!.uniform2f(pBlur.u.uDir, 0, 1);
      drawTo(T_a);
    }

    gl!.useProgram(pComp.p);
    gl!.activeTexture(gl!.TEXTURE0);
    gl!.bindTexture(gl!.TEXTURE_2D, T_s1.tex);
    gl!.uniform1i(pComp.u.uSoft, 0);
    gl!.activeTexture(gl!.TEXTURE1);
    gl!.bindTexture(gl!.TEXTURE_2D, T_rim.tex);
    gl!.uniform1i(pComp.u.uRim, 1);
    gl!.activeTexture(gl!.TEXTURE2);
    gl!.bindTexture(gl!.TEXTURE_2D, T_a.tex);
    gl!.uniform1i(pComp.u.uGlow, 2);
    gl!.uniform2f(pComp.u.uRes, W, H);
    gl!.uniform2f(pComp.u.uC, CX, CY);
    gl!.uniform2f(pComp.u.uHalf, BW / 2, BH / 2);
    gl!.uniform1f(pComp.u.uT, clock);
    gl!.uniform4fv(pComp.u.uRip, ripArr);
    gl!.uniform4f(pComp.u.uRipK, R.speed, R.width, R.decay, R.amp);
    gl!.uniform4f(pComp.u.uRipK2, R.facet, R.lobes, R.sharp, R.emit);
    gl!.uniform1f(pComp.u.uGlowGain, C.glow);
    gl!.uniform1f(pComp.u.uGlowIn, C.glowIn);
    gl!.uniform1f(pComp.u.uOccl, C.occl);
    gl!.uniform1f(pComp.u.uDim, P.dim);
    gl!.uniform1f(pComp.u.uPunch, C.punch);
    drawTo(null);

    raf = requestAnimationFrame(frame);
  }

  const onEnter = (e: PointerEvent) => {
    if (e.pointerType !== 'mouse') return;
    [ptr.x, ptr.y] = localPt(e);
    ptrS.x = ptr.x;
    ptrS.y = ptr.y;
    ptrSpeed = 0;
    on.over = true;
    sync();
  };
  const onLeave = (e: PointerEvent) => {
    if (e.pointerType === 'mouse') {
      on.over = false;
      sync();
    }
  };
  const onMove = (e: PointerEvent) => {
    if (!on.over && !on.press) return;
    [ptr.x, ptr.y] = localPt(e);
  };
  const onDown = (e: PointerEvent) => {
    [ptr.x, ptr.y] = localPt(e);
    on.press = true;
    sync();
    addRipple(ptr.x, ptr.y);
  };
  const onUp = () => {
    on.press = false;
    sync();
  };
  const onFocus = () => {
    on.focus = btn.matches(':focus-visible');
    sync();
  };
  const onBlur = () => {
    on.focus = false;
    sync();
  };
  const onKeyDown = (e: KeyboardEvent) => {
    if ((e.key !== 'Enter' && e.key !== ' ') || e.repeat) return;
    on.press = true;
    sync();
    addRipple(0, 0);
  };
  const onKeyUp = (e: KeyboardEvent) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    on.press = false;
    sync();
  };

  let lost = false;
  const onLost = (e: Event) => {
    e.preventDefault();
    lost = true;
    cancelAnimationFrame(raf);
    onContextLost?.();
  };

  btn.addEventListener('pointerenter', onEnter);
  btn.addEventListener('pointerleave', onLeave);
  window.addEventListener('pointermove', onMove, { passive: true });
  btn.addEventListener('pointerdown', onDown);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onUp);
  btn.addEventListener('focus', onFocus);
  btn.addEventListener('blur', onBlur);
  btn.addEventListener('keydown', onKeyDown);
  btn.addEventListener('keyup', onKeyUp);
  cv.addEventListener('webglcontextlost', onLost);

  if (document.activeElement === btn) onFocus();
  resize();
  raf = requestAnimationFrame(frame);

  return () => {
    cancelAnimationFrame(raf);
    resizeObserver.disconnect();
    btn.removeEventListener('pointerenter', onEnter);
    btn.removeEventListener('pointerleave', onLeave);
    window.removeEventListener('pointermove', onMove);
    btn.removeEventListener('pointerdown', onDown);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onUp);
    btn.removeEventListener('focus', onFocus);
    btn.removeEventListener('blur', onBlur);
    btn.removeEventListener('keydown', onKeyDown);
    btn.removeEventListener('keyup', onKeyUp);
    cv.removeEventListener('webglcontextlost', onLost);
    root.classList.remove('is-hot', 'is-press');
    if (!lost) {
      for (const t of targets) {
        gl.deleteFramebuffer(t.fbo);
        gl.deleteTexture(t.tex);
      }
      for (const p of programs) gl.deleteProgram(p);
      for (const s of shaders) gl.deleteShader(s);
      gl.deleteBuffer(vbo);
      gl.deleteVertexArray(vao);
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  };
}
