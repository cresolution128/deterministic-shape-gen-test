/* -------------------- Utilities: SHA-256 (WebCrypto + lightweight fallback) -------------------- */
async function sha256Hex(str){
  // UTF-8 -> bytes
  const enc = new TextEncoder();
  const data = enc.encode(str);
  if (crypto && crypto.subtle && crypto.subtle.digest){
    const hash = await crypto.subtle.digest('SHA-256', data);
    return bufferToHex(hash);
  }
  // Tiny fallback: minimal JS SHA-256 (non-optimized but small)
  return bufferToHex(fallbackSha256(data));
}
function bufferToHex(buf){
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let b of bytes) { s += ('00'+b.toString(16)).slice(-2); }
  return s;
}
/* Minimal fallback SHA-256 (works in most environments). Implementation adapted for brevity. */
function fallbackSha256(msgBytes){
  // Basic synchronous SHA-256 (non-crypto-optimized)
  // Source idea: compact implementation using standard constants
  const K = Uint32Array.from([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function ROTR(n,x){ return (x>>>n)|(x<<(32-n)) }
  function Ch(x,y,z){ return (x & y) ^ (~x & z) }
  function Maj(x,y,z){ return (x & y) ^ (x & z) ^ (y & z) }
  function Sigma0(x){ return ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x) }
  function Sigma1(x){ return ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x) }
  function sigma0(x){ return ROTR(7,x) ^ ROTR(18,x) ^ (x>>>3) }
  function sigma1(x){ return ROTR(17,x) ^ ROTR(19,x) ^ (x>>>10) }

  // Pre-processing
  let l = msgBytes.length;
  const withOne = new Uint8Array(((l + 9 + 63) >> 6) << 6); // multiple of 64
  withOne.set(msgBytes);
  withOne[msgBytes.length] = 0x80;
  const bitLen = l * 8;
  // set 64-bit big-endian length at end
  for (let i=0;i<8;i++){ withOne[withOne.length-1-i] = (bitLen >>> (i*8)) & 0xff; }

  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);

  const W = new Uint32Array(64);
  for (let i=0;i<withOne.length;i+=64){
    // message schedule
    for (let t=0;t<16;t++){
      W[t] = (withOne[i + t*4] << 24) | (withOne[i + t*4 + 1] << 16) | (withOne[i + t*4 + 2] << 8) | (withOne[i + t*4 + 3]);
    }
    for (let t=16;t<64;t++){
      W[t] = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) >>> 0;
    }
    let a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7];
    for (let t=0;t<64;t++){
      const T1 = (h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]) >>> 0;
      const T2 = (Sigma0(a) + Maj(a,b,c)) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0;
      d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  // return ArrayBuffer
  const out = new Uint8Array(32);
  for (let i=0;i<8;i++){
    out[i*4] = (H[i] >>> 24) & 0xff;
    out[i*4+1] = (H[i] >>> 16) & 0xff;
    out[i*4+2] = (H[i] >>> 8) & 0xff;
    out[i*4+3] = H[i] & 0xff;
  }
  return out.buffer;
}

/* -------------------- PRNG: splitmix32 -> xoshiro128** -------------------- */
function splitmix32Factory(seed){
  let z = seed >>> 0;
  return function(){
    z = (z + 0x9e3779b9) >>> 0;
    let t = z;
    t = Math.imul(t ^ (t >>> 15), 0x85ebca6b) >>> 0;
    t = Math.imul(t ^ (t >>> 13), 0xc2b2ae35) >>> 0;
    return (t ^ (t >>> 16)) >>> 0;
  };
}
function xoshiro128pFactory(a,b,c,d){
  let s0=a>>>0,s1=b>>>0,s2=c>>>0,s3=d>>>0;
  function rotl(x,k){ return ((x<<k) | (x>>> (32-k))) >>> 0; }
  return {
    nextUint32(){
      const result = rotl((s1 * 5) >>> 0, 7);
      const res = (Math.imul(result, 9) ) >>> 0;
      const t = (s1 << 9) >>> 0;
      s2 ^= s0; s3 ^= s1; s1 ^= s2; s0 ^= s3;
      s2 ^= t;
      s3 = rotl(s3, 11);
      return res >>> 0;
    },
    nextFloat(){ return (this.nextUint32() >>> 0) / 0x100000000; },
    nextRange(min,max){ return min + this.nextFloat() * (max-min); }
  };
}
function makeRNGFromSeedHex(seedHex){
  let base = 0;
  for (let i=0;i<seedHex.length;i+=8){
    base ^= parseInt(seedHex.slice(i,i+8),16) >>> 0;
  }
  const sm = splitmix32Factory(base);
  const a = sm(); const b = sm(); const c = sm(); const d = sm();
  return xoshiro128pFactory(a,b,c,d);
}

/* -------------------- Deterministic JSON stringify (sorted keys) -------------------- */
function stableStringify(obj){
  if (obj === null) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

/* -------------------- Core: generate params, layers, svg, json -------------------- */
async function computeSeedHexFromInputs(inputs){
  const seedString = `${inputs.huid}|${inputs.ts}|${inputs.P},${inputs.I},${inputs.E},${inputs.C}|${inputs.context}|${inputs.style}|v12`;
  const seedHex = await sha256Hex(seedString);
  return { seedString, seedHex };
}

function deriveParams(rng, inputs){
  const rings = 6 + Math.floor(rng.nextRange(0,5));
  const turns = 2 + Math.floor(rng.nextRange(0,6));
  const raysLevel = inputs.style === 'geometric' ? Math.floor(rng.nextRange(0,101)) : 0;
  const paletteHue = Math.floor(rng.nextRange(0,360));
  const pointsDensity = 140 + Math.floor(rng.nextRange(0,160));
  const lineScale = 0.9 + rng.nextRange(0,0.6);
  return { rings, turns, raysLevel, paletteHue, pointsDensity, lineScale };
}

// Reference palettes and accent
const PALETTES = {
  gold:   { main: '#D4AF37', light: '#FFE6A3', shade: '#8C6D1F' },
  red:    { main: '#E14A44', light: '#FFB3AF', shade: '#8E2D28' },
  indigo: { main: '#4B3FBF', light: '#B7B3F3', shade: '#2B2570' },
  copper: { main: '#C8761B', light: '#F1B07A', shade: '#8A4F14' },
  olo:    { main: '#46C1B7', light: '#AEE7E2', shade: '#2D8079' },
  bg:     '#0F1417'
};
const ACCENT = '#8fb4ff';

// --- sfc32 PRNG (reference) ---
function sfc32(a, b, c, d) {
  return function() {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    var t = (a + b) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21 | c >>> 11);
    d = (d + 1) | 0;
    t = (t + d) | 0;
    c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  };
}
function makeSfc32FromSeedHex(seedHex) {
  return sfc32(
    parseInt(seedHex.slice(0, 8), 16),
    parseInt(seedHex.slice(8, 16), 16),
    parseInt(seedHex.slice(16, 24), 16),
    parseInt(seedHex.slice(24, 32), 16)
  );
}
// --- Catmull-Rom spline (reference) ---
function catmullRomPath(pts, closed = true) {
  const P = pts.slice();
  if (closed) {
    P.unshift(pts[pts.length - 1]);
    P.push(pts[0], pts[1]);
  }
  let d = `M ${P[1].x.toFixed(2)} ${P[1].y.toFixed(2)}`;
  for (let i = 1; i < P.length - 2; i++) {
    const p0 = P[i - 1], p1 = P[i], p2 = P[i + 1], p3 = P[i + 2];
    const c1x = p1.x + (p2.x - p0.x) / 6, c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6, c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${c1x.toFixed(2)} ${c1y.toFixed(2)}, ${c2x.toFixed(2)} ${c2y.toFixed(2)}, ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`;
  }
  return d;
}
// --- Emblem shape generators (reference logic) ---
function genOrganica({cx, cy, rnd, energies, lineScale}) {
  const [P, I, E, C] = energies;
  const R0 = 110 + I * 4, a1 = 0.15 + E * 0.03, a2 = 0.10 + C * 0.02;
  const k1 = 3 + Math.floor(rnd() * 3 + P * 0.2), k2 = 5 + Math.floor(rnd() * 4 + P * 0.1);
  const p1 = rnd() * Math.PI * 2, p2 = rnd() * Math.PI * 2, M = 96 + P * 8, pts = [];
  for (let i = 0; i < M; i++) {
    const th = i / M * Math.PI * 2;
    const r = R0 * (1 + a1 * Math.sin(k1 * th + p1) + a2 * Math.sin(k2 * th + p2));
    pts.push({ x: cx + r * Math.cos(th), y: cy + r * Math.sin(th) });
  }
  const coreR = 28 + ((P + I + E + C) / 4) * 3 * lineScale;
  return { d: catmullRomPath(pts, true), core: { cx, cy, r: coreR.toFixed(2) } };
}
function genGeometric({cx, cy, rnd, energies, raysLevel, lineScale}) {
  const [P, I, E, C] = energies;
  const n = 4 + (C) * 0.12;
  const k = 3 + Math.floor(rnd() * 3 + P * 0.2);
  const R = 110 + I * 4;
  const mA = 0.12 + E * 0.03;
  const M = 2 * k * 24;
  const rot = rnd() * Math.PI * 2;
  let pts = [];
  for (let i = 0; i < M; i++) {
    const th = i / M * Math.PI * 2 + rot;
    const base = 1 / Math.sqrt(Math.pow(Math.abs(Math.cos(th)), 2 / n) + Math.pow(Math.abs(Math.sin(th)), 2 / n));
    const mod = 1 + mA * Math.cos(k * th);
    pts.push({ x: cx + R * base * mod * Math.cos(th), y: cy + R * base * mod * Math.sin(th) });
  }
  // Rays
  let rays = null;
  if (raysLevel > 0) {
    const count = Math.max(1, Math.round((24 + 6 * C) * (Math.max(0, Math.min(100, raysLevel)) / 100)));
    const step = Math.PI * 2 / count, items = [];
    for (let i = 0; i < count; i++) {
      const a = i * step + rot * 0.5;
      const w = 0.3 + (3.5 - 0.3) * ((Math.sin(i * 2.399) + 1) / 2);
      items.push({
        x1: cx + Math.cos(a) * (R * 0.45),
        y1: cy + Math.sin(a) * (R * 0.45),
        x2: cx + Math.cos(a) * (R * 1.1),
        y2: cy + Math.sin(a) * (R * 1.1),
        w: w.toFixed(2)
      });
    }
    rays = { count, items };
  }
  return { d: catmullRomPath(pts, true), rays };
}
function chaikin(pts, it = 1) {
  let p = pts.slice();
  for (let k = 0; k < it; k++) {
    const out = [];
    for (let i = 0; i < p.length - 1; i++) {
      const A = p[i], B = p[i + 1];
      out.push({ x: A.x * 0.75 + B.x * 0.25, y: A.y * 0.75 + B.y * 0.25 });
      out.push({ x: A.x * 0.25 + B.x * 0.75, y: A.y * 0.25 + B.y * 0.75 });
    }
    p = out;
  }
  return p;
}
function genCalligraphic({cx, cy, rnd, energies, penMul, penSmooth, lineScale}) {
  const [P, I, E, C] = energies;
  const R0 = 105 + I * 5, a1 = 0.14 + E * 0.02, a2 = 0.10 + C * 0.02;
  const k1 = 2 + Math.floor(rnd() * 3), k2 = 5 + Math.floor(rnd() * 3);
  const p1 = rnd() * Math.PI * 2, p2 = rnd() * Math.PI * 2, N = 80 + P * 10, ctr = [];
  for (let i = 0; i < N; i++) {
    const t = i / (N - 1), th = t * Math.PI * 2;
    const r = R0 * (1 + a1 * Math.sin(k1 * th + p1) + a2 * Math.sin(k2 * th + p2));
    ctr.push({ x: cx + r * Math.cos(th), y: cy + r * Math.sin(th) });
  }
  const base = (2.0 + E * 0.8) * (penMul || 1.6) * (lineScale || 1), varA = 0.6 + C * 0.25, varK = 3 + Math.floor(rnd() * 4);
  const left = [], right = [];
  for (let i = 0; i < ctr.length; i++) {
    const p = ctr[i], q = ctr[(i + 1) % ctr.length], dx = q.x - p.x, dy = q.y - p.y, len = Math.max(1e-6, Math.hypot(dx, dy));
    const nx = -dy / len, ny = dx / len, t = i / (ctr.length - 1), w = base * (1 + varA * Math.sin(varK * t * Math.PI * 2));
    left.push({ x: p.x + nx * w, y: p.y + ny * w });
    right.push({ x: p.x - nx * w, y: p.y - ny * w });
  }
  let rib = left.concat(right.reverse());
  if (penSmooth > 0) rib = chaikin(rib, Math.max(0, Math.min(3, penSmooth | 0)));
  let d = `M ${rib[0].x.toFixed(2)} ${rib[0].y.toFixed(2)}`;
  for (let i = 1; i < rib.length; i++) d += ` L ${rib[i].x.toFixed(2)} ${rib[i].y.toFixed(2)}`;
  d += ' Z';
  const coreR = 26 + ((P + I + E + C) / 4) * 2.5;
  return { d, core: { cx, cy, r: coreR.toFixed(2) } };
}

function renderSpiralVarWidth({cx, cy, rnd, energies, intensity}) {
  const [P, I, E, C] = energies;
  const TAU = Math.PI * 2;
  const turns = 2 + Math.round((I + C) / 2);
  const steps = 260 + P * 40;
  const rMax = 190 + I * 6;
  const baseW = (1.4 + E * 0.6) * intensity;
  const ampW = (0.8 + C * 0.3) * intensity;
  const kW = 3 + Math.floor(rnd() * 4);
  const ctr = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const a = t * turns * TAU;
    const r = 10 + rMax * t;
    ctr.push({ x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r, t });
  }
  const left = [], right = [];
  for (let i = 0; i < ctr.length - 1; i++) {
    const p = ctr[i], q = ctr[i + 1], dx = q.x - p.x, dy = q.y - p.y, len = Math.max(1e-6, Math.hypot(dx, dy));
    const nx = -dy / len, ny = dx / len;
    const w = baseW * (1 + ampW * Math.sin(kW * p.t * TAU));
    left.push({ x: p.x + nx * w, y: p.y + ny * w });
    right.push({ x: p.x - nx * w, y: p.y - ny * w });
  }
  const rib = left.concat(right.reverse());
  let d = `M ${rib[0].x.toFixed(2)} ${rib[0].y.toFixed(2)}`;
  for (let i = 1; i < rib.length; i++) d += ` L ${rib[i].x.toFixed(2)} ${rib[i].y.toFixed(2)}`;
  d += ' Z';
  return d;
}
function buildLayersSVG(rng, params, inputs) {
  const W = 512, H = 512, cx = W / 2, cy = H / 2;
  const palette = PALETTES[inputs.palette] || PALETTES.gold;
  // Use sfc32 PRNG for geometry
  let localSeedHex = (window._last && window._last.seedHex) || '0'.repeat(64);
  if (inputs._seedHex) localSeedHex = inputs._seedHex;
  const prng = makeSfc32FromSeedHex(localSeedHex);
  // --- SVG <defs> ---
  let defs = `<defs>`;
  defs += `<filter id="softglow"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>`;
  defs += `<radialGradient id="palGrad"><stop offset="0%" stop-color="${palette.light}"/><stop offset="70%" stop-color="${palette.main}"/><stop offset="100%" stop-color="${palette.shade}"/></radialGradient>`;
  defs += `</defs>`;
  // --- DOTS ---
  const dotTones = inputs.palette === 'olo' ? ['#0D221B','#2B7E75','#E4D6B0'] : [palette.light, palette.main, palette.shade];
  const dotsCount = Math.min(400, Math.floor((inputs.pointsDensity||params.pointsDensity)/1.5));
  const minDist = 13;
  let placed = [];
  let dots = '';
  let attempts = 0;
  while (placed.length < dotsCount && attempts < dotsCount*20) {
    attempts++;
    const x = rng.nextRange(0, W);
    const y = rng.nextRange(0, H);
    const distToCenter = Math.hypot(x-cx, y-cy);
    if (distToCenter < 60) continue;
    let ok = true;
    for (let j=0;j<placed.length;j++) {
      const d2 = (x-placed[j][0])**2 + (y-placed[j][1])**2;
      if (d2 < minDist*minDist) { ok = false; break; }
    }
    if (!ok) continue;
    const tone = dotTones[placed.length % dotTones.length];
    const r = Math.max(0.8, rng.nextRange(0.8, 2.0));
    dots += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(2)}" fill="${tone}" fill-opacity="1"/>`;
    placed.push([x,y]);
  }
  dots = `<g opacity="1">${dots}</g>`;
  // --- SPIRAL/COIL (reference logic) ---
  const spiralPath = renderSpiralVarWidth({ cx, cy, rnd: prng, energies: [inputs.P, inputs.I, inputs.E, inputs.C], intensity: inputs.wavesIntensity || 0.6 });
  const spiral = `<path d="${spiralPath}" fill="#8fb4ff" fill-opacity="0.12" stroke="none"/>`;
  // --- EMBLEM & RAYS LAYER (reference logic) ---
  let emblem = '';
  let raysGroup = '';
  let shadow = '';
  // Use sfc32 PRNG for geometry
  if (inputs.style === 'organica') {
    const out = genOrganica({ cx, cy, rnd: prng, energies: [inputs.P, inputs.I, inputs.E, inputs.C], lineScale: inputs.lineScale || 1 });
    shadow = `<path d="${out.d} Z" fill="none" stroke="#fff" stroke-width="4.5" opacity="0.08"/>`;
    emblem = `<path d="${out.d} Z" fill="none" stroke="${palette.main}" stroke-width="2.8" opacity="0.93"/>`;
    emblem += `<circle cx="${cx}" cy="${cy}" r="${out.core.r}" stroke="${palette.main}" stroke-opacity="0.7" stroke-width="1" fill="none"/>`;
  } else if (inputs.style === 'geometric') {
    const out = genGeometric({ cx, cy, rnd: prng, energies: [inputs.P, inputs.I, inputs.E, inputs.C], raysLevel: inputs.raysLevel || 40, lineScale: inputs.lineScale || 1 });
    shadow = `<path d="${out.d} Z" fill="none" stroke="#fff" stroke-width="4.5" opacity="0.08"/>`;
    emblem = `<path d="${out.d} Z" fill="none" stroke="${palette.main}" stroke-width="2.8" opacity="0.93"/>`;
    if (out.rays && out.rays.items) {
      for (const r of out.rays.items) {
        raysGroup += `<line x1="${r.x1}" y1="${r.y1}" x2="${r.x2}" y2="${r.y2}" stroke="${ACCENT}" stroke-width="${r.w}" opacity="0.35"/>`;
      }
      raysGroup = `<g>${raysGroup}</g>`;
    }
  } else if (inputs.style === 'calligraphic') {
    const out = genCalligraphic({ cx, cy, rnd: prng, energies: [inputs.P, inputs.I, inputs.E, inputs.C], penMul: inputs.penMul, penSmooth: inputs.penSmooth, lineScale: inputs.lineScale || 1 });
    emblem = `<path d="${out.d} Z" fill="url(#palGrad)" fill-opacity="0.92" stroke="none" stroke-width="0"/>`;
  }
  // --- CORE ---
  let core = `<circle cx="${cx}" cy="${cy}" r="12" fill="none" stroke="${palette.main}" stroke-opacity="0.7" stroke-width="1.8"/>`;
  core += `<circle cx="${cx}" cy="${cy}" r="6" fill="${ACCENT}" fill-opacity="0.18"/>`;
  // --- GROUPS & ORDER ---
  let svgContent = `${defs}${dots}${spiral}${raysGroup}${shadow}${emblem}${core}`;
  return { svgContent };
}

// --- Hash helpers ---
async function keccak256Hex(str) {
  // Placeholder: in production, use a pure JS keccak256 (or import from reference)
  // For now, fallback to sha256Hex for demo
  return await sha256Hex(str);
}
// --- Deterministic JSON serialization (sorted keys, normalized numbers) ---
function stableStringify(obj) {
  if (obj === null) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}
// --- Main export logic ---
async function generateAll(inputs) {
  const { seedString, seedHex } = await computeSeedHexFromInputs(inputs);
  const rng = makeRNGFromSeedHex(seedHex);
  const params = deriveParams(rng, inputs);
  const rng2 = makeRNGFromSeedHex(seedHex);
  const { svgContent } = buildLayersSVG(rng2, params, inputs);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
    <rect width="100%" height="100%" fill="#0F1417"/>
    ${svgContent}
  </svg>`;
  // Hashes
  const huidHash = await keccak256Hex(inputs.huid);
  const svgHash = await sha256Hex(svg);
  // JSON metadata
  const jsonMeta = {
    seedHex,
    seedString,
    params: { ...params },
    inputs: { ...inputs },
    ids: {
      huidHash,
      svgHash,
    },
    export: {
      svg: true,
      png512: true,
      png1024: true,
      json: true
    },
    view: {
      width: 512,
      height: 512,
      bg: '#0F1417'
    }
  };
  const jsonNoHash = stableStringify(jsonMeta);
  const jsonHash = await sha256Hex(jsonNoHash);
  const hashHex = jsonHash;
  jsonMeta.ids.jsonHash = jsonHash;
  jsonMeta.hashHex = hashHex;
  return { svg, jsonOut: jsonMeta, seedHex, seedString };
}

/* -------------------- Export helpers -------------------- */
function download(filename, data, type='application/octet-stream'){
  const blob = new Blob([data], {type});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=filename; document.body.appendChild(a); a.click();
  setTimeout(()=>{ URL.revokeObjectURL(url); a.remove(); },300);
}
function svgToPng(svgStr, size=512){
  return new Promise(resolve=>{
    const img = new Image();
    const svgBlob = new Blob([svgStr], {type:'image/svg+xml;charset=utf-8'});
    const url = URL.createObjectURL(svgBlob);
    img.onload = ()=> {
      const canvas = document.createElement('canvas');
      canvas.width = size; canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = PALETTES.bg.bg; ctx.fillRect(0,0,canvas.width,canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob(blob => { URL.revokeObjectURL(url); resolve(blob); }, 'image/png');
    };
    img.onerror = ()=> { URL.revokeObjectURL(url); resolve(null); };
    img.src = url;
  });
}

/* -------------------- UI wiring -------------------- */
const el = id => document.getElementById(id);
async function readInputs(){
  return {
    huid: el('huid').value.trim(),
    ts: el('ts').value.trim(),
    P: Number(el('P').value || 0),
    I: Number(el('I').value || 0),
    E: Number(el('E').value || 0),
    C: Number(el('C').value || 0),
    context: el('context').value,
    style: el('style').value,
    palette: el('palette').value,
    pointsDensity: Number(el('pointsDensity')?.value || 220),
    lineScale: Number(el('lineScale')?.value || 1),
    raysLevel: Number(el('raysLevel')?.value || 60),
    penMul: Number(el('penMul')?.value || 1.6),
    penSmooth: Number(el('penSmooth')?.value || 2),
    wavesIntensity: Number(el('wavesIntensity')?.value || 0.6),
    pngAlpha: Number(el('pngAlpha')?.value || 1),
    autoRegen: !!el('autoRegen')?.checked
  };
}
// Show/hide advanced blocks based on style
function updateAdvancedBlocks() {
  const style = el('style').value;
  el('geoBlock').style.display = style === 'geometric' ? '' : 'none';
  el('calBlock').style.display = style === 'calligraphic' ? '' : 'none';
}
el('style').addEventListener('change', updateAdvancedBlocks);
updateAdvancedBlocks();
// Now button for timestamp
if (el('tsNow')) {
  el('tsNow').addEventListener('click',()=>{
    el('ts').value = Date.now();
    if (el('autoRegen')?.checked) renderAndShow();
  });
}
// Random energies button
if (el('randE')) {
  el('randE').addEventListener('click',()=>{
    el('P').value = Math.floor(Math.random()*6);
    el('I').value = Math.floor(Math.random()*6);
    el('E').value = Math.floor(Math.random()*6);
    el('C').value = Math.floor(Math.random()*6);
    el('P_val').textContent = el('P').value;
    el('I_val').textContent = el('I').value;
    el('E_val').textContent = el('E').value;
    el('C_val').textContent = el('C').value;
    if (el('autoRegen')?.checked) renderAndShow();
  });
}
// Auto-regen logic
const autoInputs = [
  'huid','ts','P','I','E','C','context','style','palette',
  'pointsDensity','lineScale','raysLevel','penMul','penSmooth','wavesIntensity','pngAlpha'
];
autoInputs.forEach(id=>{
  const elem = el(id);
  if (elem) {
    elem.addEventListener('input',()=>{
      if (el('autoRegen')?.checked) renderAndShow();
    });
  }
});
async function renderAndShow(){
  const inputs = await readInputs();
  const res = await generateAll(inputs);
  el('seedHexOut').textContent = res.seedHex;
  const jsonPretty = JSON.stringify(res.jsonOut, null, 2);
  el('jsonOut').textContent = jsonPretty;
  el('hashHexOut').textContent = res.jsonOut.hashHex;
  el('svgPreview').outerHTML = res.svg.replace('<svg','<svg id="svgPreview"');
  window._last = res;
}
el('gen').addEventListener('click', renderAndShow);
el('exportSvg').addEventListener('click', ()=> {
  if (!window._last) return alert('Generate first');
  download('glyph.svg', window._last.svg, 'image/svg+xml');
});
el('exportPNG').addEventListener('click', async ()=> {
  if (!window._last) return alert('Generate first');
  const blob = await svgToPng(window._last.svg,512);
  if (blob) download('glyph-512.png', blob, 'image/png'); else alert('PNG export failed');
});
el('exportPNG2k').addEventListener('click', async ()=> {
  if (!window._last) return alert('Generate first');
  const blob = await svgToPng(window._last.svg,1024);
  if (blob) download('glyph-1024.png', blob, 'image/png'); else alert('PNG export failed');
});
el('exportJSON').addEventListener('click', ()=> {
  if (!window._last) return alert('Generate first');
  const jsonStr = JSON.stringify(window._last.jsonOut, null, 2);
  download('glyph.json', jsonStr, 'application/json');
});

/* -------------------- Tests T1 / T2 -------------------- */
el('runT1').addEventListener('click', async ()=>{
  const inputs = await readInputs();
  const hashes = [];
  for (let i=0;i<3;i++){
    const r = await generateAll(inputs);
    hashes.push(r.jsonOut.hashHex);
  }
  el('tvReport').textContent = `T1 hashes:\n${hashes.join('\n')}\nAll equal: ${hashes[0]===hashes[1] && hashes[1]===hashes[2]}`;
});

el('runT2').addEventListener('click', async ()=>{
  const inputsBase = await readInputs();
  const seen = new Set();
  let dup = 0;
  for (let i=0;i<200;i++){
    const inputs = Object.assign({}, inputsBase, { ts: String(Number(inputsBase.ts) + i) });
    const r = await generateAll(inputs);
    if (seen.has(r.seedHex)) dup++; else seen.add(r.seedHex);
  }
  el('tvReport').textContent = `T2: Generated 200 seeds — duplicates: ${dup}`;
});

/* -------------------- Validate TV control vectors -------------------- */
const TVs = [
  {name:'TV1-Organica', inputs:{huid:'H-DET-001',ts:'1723654321123',P:2,I:3,E:2,C:4,context:'verify',style:'organica'}, expect:'cae26fdb37a8e2ac05db843c665441ebf23b4a5387c24bcf332f6401e692fb1f', note:'rings=8 turns=6'},
  {name:'TV2-Geometric', inputs:{huid:'H-DET-002',ts:'1723654321123',P:1,I:4,E:3,C:2,context:'registration',style:'geometric'}, expect:'0852217fe382243d533d8f4140c4fdd9eb1900b9f78c3bd293ba16f9e32d71c6', note:'rings=7 turns=5 rays=22'},
  {name:'TV3-Calligraphic', inputs:{huid:'H-DET-003',ts:'1723654321123',P:5,I:1,E:4,C:0,context:'payment_confirm',style:'calligraphic'}, expect:'3ac43403cf202974d565d9717b93f55bdbefd7fce851814fbc28c7a9d1377ad1', note:'rings=11 turns=2'},
  {name:'TV4-Geometric100', inputs:{huid:'H-DET-004',ts:'1723654321123',P:0,I:5,E:1,C:4,context:'verify',style:'geometric'}, expect:'fa5e49853236e5c0ae8565d6d9e69fb0f3e3abedebb946f9cf236f9b0be69d6d', note:'rings=6 turns=6 rays=48'},
  {name:'TV7-Geometric0', inputs:{huid:'H-DET-007',ts:'1723654321123',P:1,I:1,E:1,C:1,context:'other',style:'geometric'}, expect:'0435a16f7c2e5ee5bded0b8eacb285a7764df2c8c2a6e4e5426f2d122bd5c50d', note:'rings=7 turns=3 rays=0'},
  {name:'TV10-Geometric35', inputs:{huid:'H-DET-010',ts:'1723654321123',P:2,I:5,E:4,C:3,context:'verify',style:'geometric'}, expect:'58a10cbb70fb6a8a8dd0fca720f2e0d71f5e3ea5e7e1b98fca7f6ed78e1a0b35', note:'rings=8 turns=6 rays=15'},
];
el('validateTVs').addEventListener('click', async ()=>{
  let report = '';
  for (let t of TVs){
    const { seedHex } = await computeSeedHexFromInputs(t.inputs);
    const ok = seedHex === t.expect;
    report += `${t.name}: computed=${seedHex}\nexpected=${t.expect}\nMATCH=${ok}\nnote=${t.note}\n\n`;
  }
  el('tvReport').textContent = report;
});

/* -------------------- initial render -------------------- */
renderAndShow();
