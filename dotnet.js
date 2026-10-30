/*
 * PEek — dotnet.js
 * Reverse engineers .NET programs without running them. .NET files keep a structured description of
 * themselves, so this reads the metadata tables (ECMA-335) and walks the IL code of each method to see
 * what it calls, then looks for hardcoded settings such as a server address and port.
 * Input is hostile: every read is bounds-checked and every loop is capped.
 */
(function (root) {
  'use strict';

  const MAX_ROWS = 300000;
  const MAX_METHODS = 60000;
  const MAX_IL = 64 * 1024 * 1024;
  const MAX_CALLS = 8000;
  const MAX_LIST = 400;

  // Coded index: [tag bits, tables it can point to]
  const CODED = {
    TypeDefOrRef: [2, [2, 1, 27]], HasConstant: [2, [4, 8, 23]],
    HasCustomAttribute: [5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]],
    HasFieldMarshal: [1, [4, 8]], HasDeclSecurity: [2, [2, 6, 32]], MemberRefParent: [3, [2, 1, 26, 6, 27]],
    HasSemantics: [1, [20, 23]], MethodDefOrRef: [1, [6, 10]], MemberForwarded: [1, [4, 6]],
    Implementation: [2, [38, 35, 39]], CustomAttributeType: [3, [6, 10]], ResolutionScope: [2, [0, 26, 35, 1]],
    TypeOrMethodDef: [1, [2, 6]],
  };

  // Columns: 2 or 4 = fixed bytes, s/g/b = heap index, number string 'tN' = table, otherwise a coded index.
  const SCHEMA = {
    0: [2, 's', 'g', 'g', 'g'], 1: ['ResolutionScope', 's', 's'], 2: [4, 's', 's', 'TypeDefOrRef', 't4', 't6'], 3: ['t4'],
    4: [2, 's', 'b'], 5: ['t6'], 6: [4, 2, 2, 's', 'b', 't8'], 7: ['t8'], 8: [2, 2, 's'], 9: ['t2', 'TypeDefOrRef'],
    10: ['MemberRefParent', 's', 'b'], 11: [2, 'HasConstant', 'b'], 12: ['HasCustomAttribute', 'CustomAttributeType', 'b'],
    13: ['HasFieldMarshal', 'b'], 14: [2, 'HasDeclSecurity', 'b'], 15: [2, 4, 't2'], 16: [4, 't4'], 17: ['b'], 18: ['t2', 't20'],
    19: ['t20'], 20: [2, 's', 'TypeDefOrRef'], 21: ['t2', 't23'], 22: ['t23'], 23: [2, 's', 'b'], 24: [2, 't6', 'HasSemantics'],
    25: ['t2', 'MethodDefOrRef', 'MethodDefOrRef'], 26: ['s'], 27: ['b'], 28: [2, 'MemberForwarded', 's', 't26'], 29: [4, 't4'],
    30: [4, 4], 31: [4], 32: [4, 2, 2, 2, 2, 4, 'b', 's', 's'], 33: [4], 34: [4, 4, 4], 35: [2, 2, 2, 2, 4, 'b', 's', 's', 'b'],
    36: [4, 't35'], 37: [4, 4, 4, 't35'], 38: [4, 's', 'b'], 39: [4, 4, 's', 's', 'Implementation'], 40: [4, 4, 's', 'Implementation'],
    41: ['t2', 't2'], 42: [2, 2, 'TypeOrMethodDef', 's'], 43: ['MethodDefOrRef', 'b'], 44: ['t42', 'TypeDefOrRef'],
  };

  // Operand sizes for IL opcodes. Anything not listed has no operand.
  const ONE_BYTE = new Uint8Array(256);
  for (const op of [0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x1f, 0xde]) ONE_BYTE[op] = 1;
  for (let op = 0x2b; op <= 0x37; op++) ONE_BYTE[op] = 1;
  for (const op of [0x20, 0x22, 0x27, 0x28, 0x29, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
    0x81, 0x8c, 0x8d, 0x8f, 0xa3, 0xa4, 0xa5, 0xc2, 0xc6, 0xd0, 0xdd]) ONE_BYTE[op] = 4;
  for (let op = 0x38; op <= 0x44; op++) ONE_BYTE[op] = 4;
  ONE_BYTE[0x21] = 8;
  ONE_BYTE[0x23] = 8;
  const TWO_BYTE = { 0x06: 4, 0x07: 4, 0x09: 2, 0x0a: 2, 0x0b: 2, 0x0c: 2, 0x0d: 2, 0x0e: 2, 0x12: 1, 0x15: 4, 0x16: 4, 0x1c: 4 };

  const CONFIG_NAME = /host|server|domain|port|mutex|mtx|c2|gate|panel|\burl\b|install|startup|pastebin|group|campaign|webhook|botid|token|\bkey\b/i;
  const HOST_VALUE = /^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24})(?::\d{2,5})?(?:[,;](?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24})(?::\d{2,5})?)*$/i;
  const NOT_HOST = /^(system|microsoft|windows|mscorlib|newtonsoft)\.|\.(dll|exe|cs|txt|json|xml|config|resources|png|ico)$/i;
  // Version numbers like 4.0.0.0 look like IPs, and names like Switch.System.IO look like domains.
  const isRealIp = (ip) => {
    const parts = ip.split(':')[0].split('.').map(Number);
    return parts.every((n) => n <= 255) && parts[0] !== 0 && parts[0] !== 127 && parts.some((n) => n > 30);
  };
  const looksHost = (v) => {
    if (v.length > 200 || !HOST_VALUE.test(v) || NOT_HOST.test(v) || v !== v.toLowerCase()) return false;
    return v.split(/[,;]/).every((h) => (/^[\d.:]+$/.test(h) ? isRealIp(h) : true));
  };

  function parse(buf, pe) {
    const u8 = new Uint8Array(buf);
    const dv = new DataView(buf);
    const ok = (o, n) => o >= 0 && o + n <= u8.length;
    const r16 = (o) => (ok(o, 2) ? dv.getUint16(o, true) : 0);
    const r32 = (o) => (ok(o, 4) ? dv.getUint32(o, true) : 0);

    const clr = pe.toOff(pe.dirs[14].rva);
    if (clr < 0) return null;
    const metaOff = pe.toOff(r32(clr + 8));
    if (metaOff < 0 || r32(metaOff) !== 0x424a5342) return null;   // "BSJB"
    const verLen = r32(metaOff + 12);
    if (verLen > 256) return null;
    const runtime = String.fromCharCode(...u8.subarray(metaOff + 16, metaOff + 16 + verLen)).replace(/\0.*$/, '');

    const streams = {};
    const nStreams = r16(metaOff + 16 + verLen + 2);
    let s = metaOff + 16 + verLen + 4;
    for (let i = 0; i < Math.min(nStreams, 16) && ok(s, 8); i++) {
      let name = '';
      let p = s + 8;
      while (p < u8.length && u8[p] && name.length < 32) name += String.fromCharCode(u8[p++]);
      streams[name] = { off: metaOff + r32(s), size: r32(s + 4) };
      s = s + 8 + (((p - (s + 8)) + 4) & ~3);   // names are padded to 4 bytes, counted from their start
    }
    const tablesStream = streams['#~'] || streams['#-'];
    if (!tablesStream) return null;

    const t = tablesStream.off;
    const heapSizes = u8[t + 6];
    const sIdx = heapSizes & 1 ? 4 : 2, gIdx = heapSizes & 2 ? 4 : 2, bIdx = heapSizes & 4 ? 4 : 2;
    const rows = new Array(64).fill(0);
    let p = t + 24;
    for (let i = 0; i < 64; i++) {
      const present = i < 32 ? (r32(t + 8) >>> i) & 1 : (r32(t + 12) >>> (i - 32)) & 1;
      if (present) { rows[i] = r32(p); p += 4; }
    }
    if (rows.some((n) => n > MAX_ROWS * 10)) return null;

    const colSize = (col) => {
      if (col === 2 || col === 4) return col;
      if (col === 's') return sIdx;
      if (col === 'g') return gIdx;
      if (col === 'b') return bIdx;
      if (col[0] === 't' && /^t\d+$/.test(col)) return rows[Number(col.slice(1))] < 65536 ? 2 : 4;
      const [bits, tables] = CODED[col];
      return Math.max(...tables.map((x) => rows[x])) < (1 << (16 - bits)) ? 2 : 4;
    };
    const layout = {};
    let off = p;
    for (let i = 0; i <= 44; i++) {
      const widths = (SCHEMA[i] || []).map(colSize);
      const size = widths.reduce((a, b) => a + b, 0);
      layout[i] = { off, widths, size };
      off += size * rows[i];
    }

    const cell = (table, row, col) => {
      const l = layout[table];
      if (!l || row < 1 || row > rows[table]) return 0;
      let o = l.off + (row - 1) * l.size;
      for (let c = 0; c < col; c++) o += l.widths[c];
      return l.widths[col] === 2 ? r16(o) : r32(o);
    };

    const heapStr = (idx) => {
      const h = streams['#Strings'];
      if (!h || idx >= h.size) return '';
      let e = h.off + idx;
      const lim = Math.min(u8.length, h.off + h.size, e + 512);
      while (e < lim && u8[e]) e++;
      return new TextDecoder('utf-8').decode(u8.subarray(h.off + idx, e));
    };

    const blobLength = (o) => {
      const b = u8[o];
      if (!(b & 0x80)) return [b, 1];
      if (!(b & 0x40)) return [((b & 0x3f) << 8) | u8[o + 1], 2];
      return [(((b & 0x1f) << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]) >>> 0, 4];
    };

    const userString = (token) => {
      const h = streams['#US'];
      const idx = token & 0xffffff;
      if (!h || idx >= h.size) return '';
      const [len, used] = blobLength(h.off + idx);
      const start = h.off + idx + used;
      const n = Math.min(Math.max(0, len - 1), 8192);
      if (!ok(start, n)) return '';
      return new TextDecoder('utf-16le').decode(u8.subarray(start, start + (n & ~1)));
    };

    const typeRefName = (row) => {
      const ns = heapStr(cell(1, row, 2)), name = heapStr(cell(1, row, 1));
      return ns ? `${ns}.${name}` : name;
    };
    const typeDefName = (row) => {
      const ns = heapStr(cell(2, row, 2)), name = heapStr(cell(2, row, 1));
      return ns ? `${ns}.${name}` : name;
    };

    const memberRefName = (row) => {
      const coded = cell(10, row, 0);
      const tag = coded & 7, parent = coded >>> 3;
      const name = heapStr(cell(10, row, 1));
      if (tag === 1) return `${typeRefName(parent)}.${name}`;
      if (tag === 0) return `${typeDefName(parent)}.${name}`;
      return name;
    };

    // First row of the field and method lists owned by each type.
    const nTypes = Math.min(rows[2], MAX_ROWS);
    const nMethods = Math.min(rows[6], MAX_METHODS);
    const ownerOfMethod = new Int32Array(rows[6] + 2);
    const ownerOfField = new Int32Array(rows[4] + 2);
    for (let i = 1; i <= nTypes; i++) {
      const fStart = cell(2, i, 4), fEnd = i < rows[2] ? cell(2, i + 1, 4) : rows[4] + 1;
      const mStart = cell(2, i, 5), mEnd = i < rows[2] ? cell(2, i + 1, 5) : rows[6] + 1;
      for (let f = fStart; f < fEnd && f <= rows[4]; f++) if (f > 0) ownerOfField[f] = i;
      for (let m = mStart; m < mEnd && m <= rows[6]; m++) if (m > 0) ownerOfMethod[m] = i;
    }

    const calls = new Set();
    const settings = new Map();     // type row -> Map(field name -> value)
    const setting = (typeRow, name, value) => {
      if (!typeRow || value === null || value === undefined || value === '') return;
      if (!settings.has(typeRow)) settings.set(typeRow, new Map());
      if (settings.get(typeRow).size < 64) settings.get(typeRow).set(name, String(value));
    };

    let ilTotal = 0;
    for (let m = 1; m <= nMethods && ilTotal < MAX_IL; m++) {
      const rva = cell(6, m, 0);
      if (!rva) continue;
      const body = pe.toOff(rva);
      if (body < 0 || !ok(body, 1)) continue;
      const head = u8[body];
      let code, size;
      if ((head & 3) === 2) { code = body + 1; size = head >>> 2; }
      else if ((head & 3) === 3) { code = body + ((r16(body) >>> 12) * 4); size = r32(body + 4); }
      else continue;
      if (!ok(code, size)) continue;
      ilTotal += size;
      const isStaticInit = heapStr(cell(6, m, 3)) === '.cctor';
      let pending = null;
      const end = code + size;
      for (let i = code; i < end;) {
        const op = u8[i++];
        if (op === 0xfe) {
          const sub = u8[i++];
          i += TWO_BYTE[sub] || 0;
          pending = null;
          continue;
        }
        if (op === 0x45) { i += 4 + r32(i) * 4; pending = null; continue; }   // switch
        if (op === 0x28 || op === 0x6f || op === 0x73) {
          const token = r32(i);
          const table = token >>> 24, row = token & 0xffffff;
          if (table === 0x0a && calls.size < MAX_CALLS) calls.add(memberRefName(row));
        } else if (isStaticInit && op === 0x72) {
          pending = userString(r32(i));
        } else if (isStaticInit && op >= 0x15 && op <= 0x1e) {
          pending = op - 0x16;
        } else if (isStaticInit && (op === 0x1f || op === 0x20)) {
          pending = op === 0x1f ? u8[i] : r32(i);
        } else if (isStaticInit && op === 0x80 && pending !== null) {
          const row = r32(i) & 0xffffff;
          if ((r32(i) >>> 24) === 0x04) setting(ownerOfField[row], heapStr(cell(4, row, 1)), pending);
          pending = null;
        } else if (op !== 0x00) {
          pending = null;
        }
        i += ONE_BYTE[op];
      }
    }

    // const fields keep their value in the Constant table rather than in code.
    for (let i = 1; i <= Math.min(rows[11], MAX_ROWS); i++) {
      const coded = cell(11, i, 1);
      if ((coded & 3) !== 0 || (cell(11, i, 0) & 0xff) !== 0x0e) continue;
      const row = coded >>> 2;
      const h = streams['#Blob'];
      if (!h) continue;
      const at = h.off + cell(11, i, 2);
      if (!ok(at, 1)) continue;
      const [len, used] = blobLength(at);
      if (!ok(at + used, len)) continue;
      setting(ownerOfField[row], heapStr(cell(4, row, 1)), new TextDecoder('utf-16le').decode(u8.subarray(at + used, at + used + Math.min(len, 1024))));
    }

    const pinvokes = [];
    for (let i = 1; i <= Math.min(rows[28], MAX_LIST); i++) {
      pinvokes.push({ dll: heapStr(cell(26, cell(28, i, 3), 0)), name: heapStr(cell(28, i, 2)) });
    }
    const references = [];
    for (let i = 1; i <= Math.min(rows[35], MAX_LIST); i++) references.push(heapStr(cell(35, i, 7)));

    const types = [];
    let oddNames = 0;
    for (let i = 2; i <= nTypes; i++) {
      const name = typeDefName(i);
      if (!/^[\x21-\x7e]+$/.test(name) || /^[a-zA-Z_]{1,2}\d*$/.test(heapStr(cell(2, i, 1)))) oddNames++;
      if (types.length < MAX_LIST) types.push(name);
    }

    return {
      runtime,
      assembly: rows[32] ? heapStr(cell(32, 1, 7)) : null,
      typeCount: Math.max(0, rows[2] - 1), methodCount: rows[6], obfuscatedNames: rows[2] > 5 ? oddNames / (rows[2] - 1) : 0,
      references, pinvokes, types,
      calls: Array.from(calls).sort(),
      config: findConfig(settings, typeDefName),
    };
  }

  // Looks for a class holding what a remote-controlled program needs: somewhere to connect to.
  function findConfig(settings, typeName) {
    let best = null;
    for (const [row, fields] of settings) {
      const entries = Array.from(fields, ([name, value]) => ({ name, value: value.slice(0, 200) }));
      const hosts = entries.filter((e) => looksHost(e.value));
      const named = entries.filter((e) => CONFIG_NAME.test(e.name));
      const ports = entries.filter((e) => /^\d{2,5}(?:[,;]\d{2,5})*$/.test(e.value) && Number(e.value.split(/[,;]/)[0]) <= 65535);
      if (!hosts.length || !(ports.length || named.length >= 2)) continue;
      const score = hosts.length * 3 + ports.length * 2 + named.length;
      if (!best || score > best.score) best = { score, type: typeName(row), hosts: hosts.map((e) => e.value), ports: ports.map((e) => e.value), entries: entries.slice(0, 30) };
    }
    return best;
  }

  root.PEek = root.PEek || {};
  root.PEek.dotnet = { parse };
})(typeof window !== 'undefined' ? window : globalThis);
