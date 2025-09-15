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

function buildLayersSVG(rng, params, inputs){
  const W=512,H=512,cx=W/2,cy=H/2;
  const paletteMap = {
    gold:   { main: 'hsl(45, 90%, 60%)', tones: ['#ffe082', '#ffd54f', '#ffb300'] },
    red:    { main: 'hsl(0, 80%, 60%)', tones: ['#ff8a80', '#ff5252', '#d32f2f'] },
    indigo: { main: 'hsl(245, 70%, 60%)', tones: ['#b3aaff', '#536dfe', '#1a237e'] },
    copper: { main: 'hsl(25, 70%, 55%)', tones: ['#ffb074', '#d2691e', '#a0522d'] },
    olo:    { main: 'hsl(160, 60%, 50%)', tones: ['#a7ffeb', '#1de9b6', '#004d40'] }
  };
  const palette = paletteMap[inputs.palette] || paletteMap.gold;
  // Blue-noise dots: dart-throwing
  const dotsCount = Math.min(400, Math.floor((inputs.pointsDensity||params.pointsDensity)/1.5));
  const minDist = 13; // minimum center distance
  const dotTones = palette.tones.slice(0,3); // use 2–3 tones
  let placed = [];
  let dots = '';
  let attempts = 0;
  while (placed.length < dotsCount && attempts < dotsCount*20) {
    attempts++;
    const x = rng.nextRange(0, W);
    const y = rng.nextRange(0, H);
    // Mask: avoid emblem/spiral (simple: avoid center disk for now)
    const distToCenter = Math.hypot(x-cx, y-cy);
    if (distToCenter < 60) continue;
    // Enforce min center distance
    let ok = true;
    for (let j=0;j<placed.length;j++) {
      const d2 = (x-placed[j][0])**2 + (y-placed[j][1])**2;
      if (d2 < minDist*minDist) { ok = false; break; }
    }
    if (!ok) continue;
    // Palette tone distribution: cycle through tones
    const tone = dotTones[placed.length % dotTones.length];
    const r = Math.max(0.8, rng.nextRange(0.8, 2.0));
    const alpha = (0.38 + rng.nextRange(0,0.18)).toFixed(2);
    dots += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(2)}" fill="${tone}" fill-opacity="${alpha}"/>`;
    placed.push([x,y]);
  }
  // Draw gray coil-style spiral as background web for all styles
  let webPath = '';
  const webSteps = 180;
  const webTurns = 5 + Math.floor(rng.nextRange(0, 3)); // 5-7 turns
  const webMaxRadius = 200 + params.rings * 8;
  for (let i=0;i<=webSteps;i++){
    const t = i/webSteps;
    const angle = t * webTurns * 2 * Math.PI;
    const r = 8 + t * webMaxRadius;
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    webPath += (i===0? `M${x.toFixed(2)} ${y.toFixed(2)}` : ` L${x.toFixed(2)} ${y.toFixed(2)}`);
  }
  const grayColor = 'rgba(180,180,180,0.5)';
  const webCoil = `<path d="${webPath}" fill="none" stroke="${grayColor}" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" opacity="0.7"/>`;
  // Flower shape for the main line (replaces spiral/coil)
  const steps = 160;
  const petalCount = 6 + Math.floor(rng.nextRange(0, 3)); // 6-8 petals
  const baseRadius = 60 + params.rings * 8;
  const amplitude = 18 + params.turns * 4;
  const P = inputs.P;
  const thickness = 1 + P * 0.4;
  let path = '';
  for (let i=0;i<=steps;i++){
    const t = i/steps;
    const angle = t * 2 * Math.PI;
    const r = baseRadius + amplitude * Math.sin(petalCount * angle);
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    path += (i===0? `M${x.toFixed(2)} ${y.toFixed(2)}` : ` L${x.toFixed(2)} ${y.toFixed(2)}`);
  }
  const strokeColor = palette.main;
  const wave = `<path d="${path}" fill="none" stroke="${strokeColor}" stroke-width="${thickness}" stroke-linecap="round" stroke-linejoin="round" opacity="0.95"/>`;
  // Draw gray concentric circles (spider web) for all styles
  const rings = params.rings;
  let circlesGroup = `<g stroke="${grayColor}" stroke-width="1.6" fill="none" opacity="0.95">`;
  for (let r=0;r<rings;r++){
    const rad = 18 + r*12;
    circlesGroup += `<circle cx="${cx}" cy="${cy}" r="${rad}" />`;
  }
  circlesGroup += `</g>`;
  // Emblem: simple parametric flower or polygon depending on style
  let emblem = '';
  if (inputs.style === 'organica'){
    const petCount = 5 + Math.floor(rng.nextRange(0,4));
    let em = '';
    for (let j=0;j<petCount;j++){
      const a = (j/petCount)*2*Math.PI;
      const r = 40 + params.rings*6 + 8*Math.sin(j*2 + rng.nextRange(0,6.28));
      const x = cx + r*Math.cos(a), y = cy + r*Math.sin(a);
      em += `M${cx} ${cy} L${x.toFixed(1)} ${y.toFixed(1)} `;
    }
    emblem = `${webCoil}${circlesGroup}<g stroke="${strokeColor}" stroke-width="1.6" fill="none" opacity="0.95">${em}</g>`;
  } else if (inputs.style === 'geometric'){
    let g = `${webCoil}${circlesGroup}`;
    const rays = Math.round(params.raysLevel/100 * 48);
    g += `<g stroke="${grayColor}" stroke-width="1.6" fill="none" opacity="0.95">`;
    for (let k=0;k<rays;k++){
      const a = k / Math.max(1,rays) * Math.PI*2;
      const x1 = cx + Math.cos(a)*(params.rings*10), y1 = cy + Math.sin(a)*(params.rings*10);
      const x2 = cx + Math.cos(a)*(params.rings*28), y2 = cy + Math.sin(a)*(params.rings*28);
      g += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" />`;
    }
    g += `</g>`; emblem = g;
  } else {
    let ribbon = `<g fill="none" stroke="${strokeColor}" opacity="0.95">`;
    for (let k=0;k<3;k++){
      ribbon += `<path d="${path}" stroke-width="${2 + k*1.6}" stroke-linecap="round" stroke-linejoin="round"/>`;
    }
    ribbon += `</g>`;
    emblem = `${webCoil}${circlesGroup}${ribbon}`;
  }
  let core = `<circle cx="${cx}" cy="${cy}" r="${12 + params.rings}" fill="rgba(255, 230, 150, 0.12)"/>`;
  core += `<circle cx="${cx}" cy="${cy}" r="${6 + Math.floor(params.rings/2)}" fill="hsl(${params.paletteHue} 80% 60%)"/>`;
  // --- WAVES/RINGS LAYER ---
  // Use palette pale tones and correct alpha, match reference logic
  let waves = '';
  const ringCount = params.rings;
  const waveAlpha = 0.22 + (inputs.wavesIntensity||params.wavesIntensity||0.6)*0.18;
  for (let r=0; r<ringCount; r++) {
    // Palette: use the lightest tone, or shift main color to a pale version
    let tone = palette.tones[0];
    // Optionally, shift to a paler HSL for more reference-like look
    if (palette.main.startsWith('hsl')) {
      // e.g. hsl(45, 90%, 60%) => hsl(45, 60%, 85%)
      tone = palette.main.replace(/(\d+),\s*(\d+)%?,\s*(\d+)%?/, (m,h,s,l)=>`${h},${Math.max(30,Math.floor(s*0.7))}%,${85-(r*2)}%`);
    }
    const rad = 32 + r*22 + Math.sin(r*1.2)*4;
    const width = 2.2 + (r%2)*0.7;
    waves += `<circle cx="${cx}" cy="${cy}" r="${rad.toFixed(1)}" stroke="${tone}" stroke-width="${width.toFixed(2)}" fill="none" opacity="${waveAlpha.toFixed(2)}"/>`;
  }
  // --- SPIRAL LAYER ---
  // Variable-width spiral with Catmull-Rom smoothing, palette tones, correct alpha
  let spiral = '';
  const spiralSteps = 120;
  const spiralTurns = params.turns;
  const spiralBase = 38 + params.rings*7;
  const spiralAmp = 16 + (inputs.P||0)*2;
  const spiralAlpha = 0.32 + (inputs.wavesIntensity||params.wavesIntensity||0.6)*0.13;
  // Generate spiral points
  let spiralPts = [];
  for (let i=0; i<=spiralSteps; i++) {
    const t = i/spiralSteps;
    const angle = t * spiralTurns * 2 * Math.PI;
    const r = spiralBase + spiralAmp * Math.sin(spiralTurns*1.2 * t + Math.cos(t*2));
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    spiralPts.push([x, y]);
  }
  // Catmull-Rom smoothing
  function catmullRomSpline(pts, tension=0.5) {
    let d = '';
    for (let i=0; i<pts.length-1; i++) {
      const p0 = pts[i-1] || pts[i];
      const p1 = pts[i];
      const p2 = pts[i+1];
      const p3 = pts[i+2] || pts[i+1];
      const c1x = p1[0] + (p2[0]-p0[0])/6*tension;
      const c1y = p1[1] + (p2[1]-p0[1])/6*tension;
      const c2x = p2[0] - (p3[0]-p1[0])/6*tension;
      const c2y = p2[1] - (p3[1]-p1[1])/6*tension;
      if (i===0) d += `M${p1[0].toFixed(2)} ${p1[1].toFixed(2)}`;
      d += ` C${c1x.toFixed(2)} ${c1y.toFixed(2)},${c2x.toFixed(2)} ${c2y.toFixed(2)},${p2[0].toFixed(2)} ${p2[1].toFixed(2)}`;
    }
    return d;
  }
  const spiralPath = catmullRomSpline(spiralPts, 0.55);
  // Use a pale palette tone
  let spiralTone = palette.tones[0];
  if (palette.main.startsWith('hsl')) {
    spiralTone = palette.main.replace(/(\d+),\s*(\d+)%?,\s*(\d+)%?/, (m,h,s,l)=>`${h},${Math.max(25,Math.floor(s*0.5))}%,${92}%`);
  }
  spiral = `<path d="${spiralPath}" fill="none" stroke="${spiralTone}" stroke-width="2.2" opacity="${spiralAlpha.toFixed(2)}"/>`;
  const svgLayers = { dots, wave, emblem, core };
  const svgContent = `${dots}${wave}${emblem}${core}`;
  return { svgContent, svgLayers };
}

async function generateAll(inputs){
  const { seedString, seedHex } = await computeSeedHexFromInputs(inputs);
  const rng = makeRNGFromSeedHex(seedHex);
  const params = deriveParams(rng, inputs);
  const rng2 = makeRNGFromSeedHex(seedHex);
  const { svgContent, svgLayers } = buildLayersSVG(rng2, params, inputs);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
    <rect width="100%" height="100%" fill="#0b0f14"/>
    ${svgContent}
  </svg>`;
  const jsonMeta = {
    seedHex,
    seedString,
    params: { ...params },
    inputs: { ...inputs },
    layers: {
      dots: { count: Math.min(400, Math.floor(params.pointsDensity/1.5)), opacityRange:[0.45,0.6] },
      wave: { turns: params.turns, thicknessEstimate: (1 + inputs.P*0.4) },
      emblem: { style: inputs.style },
      core: { rings: params.rings }
    }
  };
  const jsonNoHash = stableStringify(jsonMeta);
  const hashHex = await sha256Hex(jsonNoHash);
  const jsonOut = Object.assign({}, jsonMeta, { hashHex });
  return { svg, jsonOut, seedHex, seedString };
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
      ctx.fillStyle = '#0b0f14'; ctx.fillRect(0,0,canvas.width,canvas.height);
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
