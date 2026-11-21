const UUID_DEFAULT = '63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd';
const PROXYIP_DEFAULT = 'Bpb.yousef.isegaro.com';
const PROXY_CONCURRENT_DIAL = 2;
const TCP_CONCURRENT_DIAL = 2;

function xorBuf(buf, key) {
  const out = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
  return out;
}
async function hmacSha256(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

function 创建请求TCP连接器(request) {
  const fetcher = request?.fetcher;
  if (!fetcher || typeof fetcher.connect !== 'function') {
    throw new Error('request.fetcher.connect unavailable');
  }
  return (options, init) =>
    init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const up = (req.headers.get('Upgrade') || '').toLowerCase();
    if (up !== 'websocket') {
      await new Promise(r => setTimeout(r, 40 + Math.random() * 80));
      return new Response(html(), { status: 200, headers: { 'content-type': 'text/html;charset=utf-8' } });
    }
    return wsHandler(req, env);
  }
};

async function wsHandler(req, env) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept({ allowHalfOpen: true });
  server.binaryType = 'arraybuffer';

  const subproto = 'chat.v2';
  const st = {
    ready: false, key: null, sock: null, wr: null,
    q: [], qb: 0, dead: false,
    token: (env.UUID || UUID_DEFAULT),
    proxyip: (env.PROXYIP || PROXYIP_DEFAULT),
    TCP连接: null,  // ساخته می‌شود در dial
  };

  server.addEventListener('message', async ev => {
    if (st.dead) return;
    try {
      const d = new Uint8Array(ev.data);
      if (!st.ready) {
        const hs = parseInit(d, st.token);
        if (!hs.ok) { server.close(1002, ''); st.dead = true; return; }
        st.ready = true;
        st.key = hs.key;
        st.TCP连接 = 创建请求TCP连接器(req);  // ← اینجا ساخته می‌شود
        await dial(server, st, hs);
        const ackRaw = await hmacSha256(st.key, new TextEncoder().encode('OK'));
        await server.send(xorBuf(ackRaw.slice(0, 16), st.key));
        if (hs.payload?.byteLength) await write(st, hs.payload);
        await drain(st);
      } else if (st.wr) {
        await write(st, xorBuf(d, st.key));
      } else {
        if (st.qb + d.byteLength > 8 * 1024 * 1024) { server.close(1009, ''); st.dead = true; return; }
        st.q.push(xorBuf(d, st.key));
        st.qb += d.byteLength;
      }
    } catch (e) {
      console.error('ws msg:', e);
      server.close(1011, ''); st.dead = true; destroy(st);
    }
  });

  server.addEventListener('close', () => { st.dead = true; destroy(st); });
  server.addEventListener('error', () => { st.dead = true; destroy(st); });

  return new Response(null, { status: 101, webSocket: client, headers: { 'sec-websocket-protocol': subproto } });
}

function parseInit(data, token) {
  if (data.byteLength < 16 + 1 + 2 + 1 + 8) return { ok: false };
  const nonce = data.subarray(0, 16);
  const tb = new TextEncoder().encode(token);
  const key = new Uint8Array(16);
  for (let i = 0; i < 16; i++) key[i] = tb[i % tb.length] ^ nonce[i];
  const enc = data.subarray(16, data.byteLength - 8);
  const body = xorBuf(enc, key);
  let p = 0;
  const cmd = body[p++];
  if (cmd !== 1 && cmd !== 2) return { ok: false };
  const port = (body[p] << 8) | body[p + 1]; p += 2;
  const at = body[p++];
  let host = '';
  if (at === 1) { host = `${body[p]}.${body[p+1]}.${body[p+2]}.${body[p+3]}`; p += 4; }
  else if (at === 2) { const l = body[p++]; host = new TextDecoder().decode(body.subarray(p, p + l)); p += l; }
  else if (at === 3) { const a = []; for (let i = 0; i < 8; i++) a.push(((body[p + i*2] << 8) | body[p + i*2 + 1]).toString(16)); host = a.join(':'); p += 16; }
  else return { ok: false };
  if (!host) return { ok: false };
  return { ok: true, hostname: host, port, key, payload: body.subarray(p) };
}

// DoH
const DoH缓存 = {};
async function DoH查询(domain, rtype, doh = 'https://cloudflare-dns.com/dns-query') {
  const key = `${domain}:${rtype}`;
  const now = Date.now();
  if (DoH缓存[key] && now < DoH缓存[key].exp) return DoH缓存[key].data;
  const qtype = { A: 1, TXT: 16, AAAA: 28 }[rtype] || 1;
  const parts = domain.replace(/\.$/, '').split('.');
  const qnameParts = [];
  for (const label of parts) { const b = new TextEncoder().encode(label); qnameParts.push(new Uint8Array([b.length]), b); }
  qnameParts.push(new Uint8Array([0]));
  const qname = concat(qnameParts);
  const q = new Uint8Array(12 + qname.length + 4);
  const dv = new DataView(q.buffer);
  dv.setUint16(0, Math.floor(Math.random() * 65535));
  dv.setUint16(2, 0x0100); dv.setUint16(4, 1);
  q.set(qname, 12);
  dv.setUint16(12 + qname.length, qtype);
  dv.setUint16(12 + qname.length + 2, 1);
  try {
    const resp = await fetch(doh, { method: 'POST', headers: { 'content-type': 'application/dns-message', 'accept': 'application/dns-message' }, body: q });
    if (!resp.ok) return [];
    const buf = new Uint8Array(await resp.arrayBuffer());
    const rdv = new DataView(buf.buffer);
    const qd = rdv.getUint16(4), an = rdv.getUint16(6);
    let off = 12;
    for (let i = 0; i < qd; i++) {
      while (off < buf.length && buf[off] !== 0) { if ((buf[off] & 0xC0) === 0xC0) { off += 2; break; } off += buf[off] + 1; }
      if (buf[off] === 0) off += 1; off += 4;
    }
    const ans = [];
    for (let i = 0; i < an && off < buf.length; i++) {
      while (off < buf.length && buf[off] !== 0) { if ((buf[off] & 0xC0) === 0xC0) { off += 2; break; } off += buf[off] + 1; }
      if (buf[off] === 0) off += 1;
      const type = rdv.getUint16(off); off += 2;
      off += 2;
      const ttl = rdv.getUint32(off); off += 4;
      const rdlen = rdv.getUint16(off); off += 2;
      const rdata = buf.slice(off, off + rdlen); off += rdlen;
      let data;
      if (type === 1) data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      else if (type === 28) { const s = []; for (let j = 0; j < 16; j += 2) s.push(((rdata[j] << 8) | rdata[j+1]).toString(16)); data = s.join(':'); }
      else if (type === 16) { let o = 0; const ps = []; while (o < rdlen) { const l = rdata[o++]; ps.push(new TextDecoder().decode(rdata.slice(o, o+l))); o += l; } data = ps.join(''); }
      else data = '';
      ans.push({ type, data, ttl });
    }
    const related = ans.filter(a => a.type === qtype);
    const minTTL = related.length ? Math.min(...related.map(a => a.ttl)) : 300;
    DoH缓存[key] = { data: ans, exp: now + Math.max(minTTL, 300) * 1000 };
    return ans;
  } catch (e) { return []; }
}
function concat(arrays) {
  const total = arrays.reduce((s, a) => s + a.byteLength, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.byteLength; }
  return out;
}
function isIP(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)); }

async function 解析地址端口(proxyIP, targetDomain, uuid) {
  const 反代IP数组 = proxyIP.split(',').map(s => s.trim()).filter(Boolean);
  const 所有反代数组 = [];
  function parseHostPort(s) {
    if (s.startsWith('[')) {
      const m = s.match(/^\[([^\]]+)\]:(\d+)$/);
      if (m) return [m[1], parseInt(m[2], 10)];
    }
    const idx = s.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(s.slice(idx+1))) return [s.slice(0, idx), parseInt(s.slice(idx+1), 10)];
    return [s, 443];
  }
  function parseTXT(txtData) {
    return txtData.flatMap(d => {
      if (d.startsWith('"') && d.endsWith('"')) d = d.slice(1, -1);
      return d.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
    }).map(p => parseHostPort(p));
  }
  for (const raw of 反代IP数组) {
    let [host, port] = parseHostPort(raw);
    const tp = raw.match(/\.tp(\d+)/);
    if (tp) port = parseInt(tp[1], 10);
    if (isIP(host)) { 所有反代数组.push([host, port]); continue; }
    const [txt, a] = await Promise.all([DoH查询(host, 'TXT'), DoH查询(host, 'A')]);
    const txtData = txt.filter(r => r.type === 16).map(r => r.data);
    const txtAddrs = parseTXT(txtData);
    if (txtAddrs.length) { console.log(`[解析] ${host} TXT → ${txtAddrs.length}`); 所有反代数组.push(...txtAddrs); continue; }
    const aData = a.filter(r => r.type === 1).map(r => r.data);
    if (aData.length) { console.log(`[解析] ${host} A → ${aData.length}`); 所有反代数组.push(...aData.map(ip => [ip, port])); continue; }
    const aaaa = await DoH查询(host, 'AAAA');
    const aaaaData = aaaa.filter(r => r.type === 28).map(r => `[${r.data}]`);
    if (aaaaData.length) { console.log(`[解析] ${host} AAAA → ${aaaaData.length}`); 所有反代数组.push(...aaaaData.map(ip => [ip, port])); }
    else { console.log(`[解析] ${host} 无记录`); 所有反代数组.push([host, port]); }
  }
  const 目标根 = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
  let seed = [...(目标根 + uuid)].reduce((a, c) => a + c.charCodeAt(0), 0);
  所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
  const shuffled = [...所有反代数组].sort(() => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
  const result = shuffled.slice(0, 8);
  console.log(`[解析] 最终 ${result.length}: ${result.map(([h,p]) => `${h}:${p}`).join(', ')}`);
  return result;
}

async function connectProxyIP(TCP连接, 所有反代数组, initialData, fallbackHost, fallbackPort, 兜底 = true) {
  if (所有反代数组 && 所有反代数组.length > 0) {
    const 并发数 = Math.max(1, PROXY_CONCURRENT_DIAL);
    for (let i = 0; i < 所有反代数组.length; i += 并发数) {
      const 候选 = [];
      for (let j = 0; j < 并发数 && i + j < 所有反代数组.length; j++) {
        const [h, p] = 所有反代数组[i + j];
        候选.push({ hostname: h, port: p });
      }
      try {
        const winner = await 并发打开候选连接(TCP连接, 候选);
        if (有效数据长度(initialData) > 0) await 写入首包(winner.socket, initialData);
        return winner.socket;
      } catch (e) { console.error(`[proxyip] 批 ${i} 失败: ${e?.message || e}`); }
    }
  }
  if (兜底) {
    console.log(`[proxyip] 兜底直连 ${fallbackHost}:${fallbackPort}`);
    const sock = await 打开TCP连接(TCP连接, fallbackHost, fallbackPort);
    if (有效数据长度(initialData) > 0) await 写入首包(sock, initialData);
    return sock;
  }
  throw new Error('[proxyip] all failed');
}

async function 并发打开候选连接(TCP连接, 候选) {
  if (候选.length === 1) return { socket: await 打开TCP连接(TCP连接, 候选[0].hostname, 候选[0].port), candidate: 候选[0] };
  const attempts = 候选.map(c => 打开TCP连接(TCP连接, c.hostname, c.port).then(s => ({ socket: s, candidate: c })));
  const winner = await Promise.any(attempts);
  for (const a of attempts) a.then(w => { if (w.socket !== winner.socket) try { w.socket.close(); } catch {} }).catch(() => {});
  return winner;
}

async function 打开TCP连接(TCP连接, host, port) {
  const sock = TCP连接({ hostname: host, port });
  await withTimeout(sock.opened, 8000, `connect ${host}:${port}`);
  return sock;
}

async function 写入首包(sock, data) {
  if (有效数据长度(data) <= 0) return;
  const w = sock.writable.getWriter();
  try { await w.write(数据转Uint8Array(data)); } finally { try { w.releaseLock(); } catch {} }
}
function 数据转Uint8Array(d) {
  if (d instanceof Uint8Array) return d;
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  return new Uint8Array(d || 0);
}
function 有效数据长度(d) { return d ? (d.byteLength ?? d.length ?? 0) : 0; }

async function dial(server, st, hs) {
  const { hostname, port, payload } = hs;
  let sock = null;
  const errs = [];
  try {
    console.log(`[dial] direct ${hostname}:${port}`);
    sock = await 并发打开候选连接(st.TCP连接, Array.from({ length: TCP_CONCURRENT_DIAL }, () => ({ hostname, port }))).then(r => r.socket);
    if (有效数据长度(payload) > 0) await 写入首包(sock, payload);
    console.log(`[dial] direct OK`);
  } catch (e) {
    console.error(`[dial] direct FAIL: ${e?.message || e}`);
    errs.push('direct: ' + (e?.message || e));
    sock = null;
  }
  if (!sock && st.proxyip) {
    try {
      const 所有 = await 解析地址端口(st.proxyip, hostname, st.token);
      sock = await connectProxyIP(st.TCP连接, 所有, payload, hostname, port, true);
      console.log(`[dial] proxyip OK`);
    } catch (e) {
      console.error(`[dial] proxyip FAIL: ${e?.message || e}`);
      errs.push('proxyip: ' + (e?.message || e));
      sock = null;
    }
  }
  if (!sock) throw new Error('dial all failed: ' + errs.join(' | '));
  st.sock = sock;
  st.wr = sock.writable.getWriter();
  (async () => {
    const rd = sock.readable.getReader();
    try {
      for (;;) {
        const { done, value } = await rd.read();
        if (done) break;
        if (!value?.byteLength) continue;
        if (st.dead) break;
        await server.send(xorBuf(value, st.key));
      }
    } catch (e) { console.error('remote read:', e); }
    finally { try { rd.releaseLock(); } catch {} try { server.close(); } catch {} st.dead = true; destroy(st); }
  })();
}

async function withTimeout(p, ms, label) {
  let t;
  try { return await Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(label + ' timeout')), ms); })]); }
  finally { clearTimeout(t); }
}
async function write(st, b) { if (!st.wr) throw new Error('no writer'); await st.wr.write(b); }
async function drain(st) { while (st.q.length && st.wr) { const c = st.q.shift(); st.qb -= c.byteLength; await write(st, c); } }
function destroy(st) { try { st.wr?.releaseLock(); } catch {} try { st.sock?.close(); } catch {} st.wr = null; st.sock = null; st.q = []; st.qb = 0; }
function html() { return '<!doctype html><html><head><title>nginx</title></head><body><h1>Welcome to nginx!</h1></body></html>'; }