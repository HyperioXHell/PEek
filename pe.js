/*
 * PEek — pe.js
 * A small, defensive parser for Windows PE files (.exe, .dll, .sys, .scr).
 * Input files are untrusted and may be malformed on purpose, so every read is bounds-checked
 * and every loop is capped.
 */
(function (root) {
  'use strict';

  const MACHINES = {
    0x14c: 'x86 (32-bit)', 0x8664: 'x64 (64-bit)', 0xaa64: 'ARM64', 0x1c0: 'ARM', 0x1c4: 'ARM (Thumb-2)', 0x200: 'Itanium',
  };
  const SUBSYSTEMS = {
    1: 'Native (driver)', 2: 'Windows app (GUI)', 3: 'Console app', 9: 'Windows CE', 10: 'EFI application',
    11: 'EFI boot driver', 12: 'EFI runtime driver', 13: 'EFI ROM', 14: 'Xbox', 16: 'Windows boot application',
  };
  const LIMITS = { sections: 96, dlls: 512, funcsPerDll: 4096, exports: 4096, resources: 4096 };

  class Reader {
    constructor(buf) { this.u8 = new Uint8Array(buf); this.dv = new DataView(buf); this.len = buf.byteLength; }
    ok(off, n) { return off >= 0 && off + n <= this.len; }
    u16(off) { return this.ok(off, 2) ? this.dv.getUint16(off, true) : 0; }
    u32(off) { return this.ok(off, 4) ? this.dv.getUint32(off, true) : 0; }
    u64(off) { return this.ok(off, 8) ? Number(this.dv.getBigUint64(off, true)) : 0; }
    cstr(off, max = 256) {
      let s = '';
      for (let i = off; i >= 0 && i < this.len && i < off + max; i++) {
        const c = this.u8[i];
        if (!c) break;
        s += String.fromCharCode(c);
      }
      return s;
    }
    utf8z(off, max = 260) {
      if (off < 0) return '';
      let end = off;
      const lim = Math.min(this.len, off + max);
      while (end < lim && this.u8[end]) end++;
      return new TextDecoder('utf-8').decode(this.u8.subarray(off, end));
    }
    wstr(off, maxChars = 256) {
      let s = '';
      for (let i = 0; i < maxChars && this.ok(off + i * 2, 2); i++) {
        const c = this.dv.getUint16(off + i * 2, true);
        if (!c) break;
        s += String.fromCharCode(c);
      }
      return s;
    }
  }

  function entropy(u8, start, end) {
    const n = end - start;
    if (n <= 0) return 0;
    const counts = new Uint32Array(256);
    for (let i = start; i < end; i++) counts[u8[i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) {
      if (counts[i]) { const p = counts[i] / n; h -= p * Math.log2(p); }
    }
    return h;
  }

  function parse(buf) {
    const r = new Reader(buf);
    if (r.len < 0x40 || r.u16(0) !== 0x5a4d) return null; // "MZ"
    const peOff = r.u32(0x3c);
    if (!r.ok(peOff, 24) || r.u32(peOff) !== 0x00004550) return null; // "PE\0\0"

    const pe = {};
    const coff = peOff + 4;
    pe.machine = r.u16(coff);
    pe.machineName = MACHINES[pe.machine] || `Unknown (0x${pe.machine.toString(16)})`;
    const nSections = r.u16(coff + 2);
    pe.timestamp = r.u32(coff + 4);
    const optSize = r.u16(coff + 16);
    pe.characteristics = r.u16(coff + 18);
    pe.isDll = !!(pe.characteristics & 0x2000);

    const opt = coff + 20;
    const magic = r.u16(opt);
    if (magic !== 0x10b && magic !== 0x20b) return null;
    pe.is64 = magic === 0x20b;
    pe.linkerVersion = `${r.u8[opt + 2]}.${r.u8[opt + 3]}`;
    pe.entryRva = r.u32(opt + 16);
    pe.imageBase = pe.is64 ? r.u64(opt + 24) : r.u32(opt + 28);
    pe.sizeOfHeaders = r.u32(opt + 60);
    pe.checksumOffset = opt + 64;
    pe.subsystem = r.u16(opt + 68);
    pe.subsystemName = SUBSYSTEMS[pe.subsystem] || `Unknown (${pe.subsystem})`;
    pe.dllCharacteristics = r.u16(opt + 70);
    pe.aslr = !!(pe.dllCharacteristics & 0x40);
    pe.dep = !!(pe.dllCharacteristics & 0x100);
    pe.cfg = !!(pe.dllCharacteristics & 0x4000);

    const dirBase = opt + (pe.is64 ? 112 : 96);
    const nDirs = Math.min(r.u32(dirBase - 4), 16);
    pe.securityDirOffset = dirBase + 4 * 8;
    pe.dirs = [];
    for (let i = 0; i < 16; i++) {
      pe.dirs.push(i < nDirs ? { rva: r.u32(dirBase + i * 8), size: r.u32(dirBase + i * 8 + 4) } : { rva: 0, size: 0 });
    }

    pe.sections = [];
    let sOff = opt + optSize;
    for (let i = 0; i < Math.min(nSections, LIMITS.sections) && r.ok(sOff, 40); i++, sOff += 40) {
      const s = {
        name: r.cstr(sOff, 8),
        virtualSize: r.u32(sOff + 8), virtualAddress: r.u32(sOff + 12),
        rawSize: r.u32(sOff + 16), rawPointer: r.u32(sOff + 20), flags: r.u32(sOff + 36),
      };
      s.exec = !!(s.flags & 0x20000000);
      s.read = !!(s.flags & 0x40000000);
      s.write = !!(s.flags & 0x80000000);
      s.entropy = entropy(r.u8, Math.min(s.rawPointer, r.len), Math.min(s.rawPointer + s.rawSize, r.len));
      pe.sections.push(s);
    }

    const toOff = (rva) => {
      if (rva < 0) return -1;
      for (const s of pe.sections) {
        if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
          const delta = rva - s.virtualAddress;
          return delta < s.rawSize && s.rawPointer + delta < r.len ? s.rawPointer + delta : -1;
        }
      }
      return rva < pe.sizeOfHeaders && rva < r.len ? rva : -1;
    };

    pe.toOff = toOff;
    pe.entrySection = pe.sections.find((s) =>
      pe.entryRva >= s.virtualAddress && pe.entryRva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) || null;

    pe.imports = parseImports(r, pe, toOff);
    pe.exports = parseExports(r, toOff, pe.dirs[0]);
    pe.resources = parseResources(r, toOff, pe.dirs[2]);
    pe.versionInfo = parseVersionInfo(r, pe.resources);
    pe.manifest = parseManifest(r, pe.resources);
    pe.debug = parseDebug(r, toOff, pe.dirs[6]);
    pe.signature = parseSignature(r, pe.dirs[4]);
    pe.isDotNet = pe.dirs[14].rva !== 0;
    pe.hasTls = pe.dirs[9].rva !== 0;

    // Microsoft's linker leaves an undocumented "Rich" header in the DOS stub.
    pe.hasRich = false;
    for (let i = 0x80; i + 4 <= Math.min(peOff, r.len); i += 4) {
      if (r.u32(i) === 0x68636952) { pe.hasRich = true; break; }
    }

    // Overlay: bytes after the last section that the loader never maps. Installers keep their
    // payload here; the Authenticode signature also lives at the end, so we exclude it.
    const sectEnd = pe.sections.reduce((m, s) => Math.max(m, Math.min(s.rawPointer + s.rawSize, r.len)), pe.sizeOfHeaders);
    const sec = pe.dirs[4];
    const overlayEnd = sec.size && sec.rva >= sectEnd && sec.rva + sec.size >= r.len - 8 ? sec.rva : r.len;
    pe.overlay = { offset: sectEnd, size: Math.max(0, overlayEnd - sectEnd) };
    pe.overlay.entropy = pe.overlay.size ? entropy(r.u8, sectEnd, overlayEnd) : 0;

    return pe;
  }

  function readThunks(r, pe, toOff, rva) {
    const names = [];
    let off = toOff(rva);
    if (off < 0) return names;
    const step = pe.is64 ? 8 : 4;
    for (let i = 0; i < LIMITS.funcsPerDll && r.ok(off, step); i++, off += step) {
      const lo = r.u32(off), hi = pe.is64 ? r.u32(off + 4) : 0;
      if (!lo && !hi) break;
      const byOrdinal = pe.is64 ? hi & 0x80000000 : lo & 0x80000000;
      if (byOrdinal) { names.push('#' + (lo & 0xffff)); continue; }
      const nOff = toOff(lo & 0x7fffffff);
      names.push(nOff >= 0 ? r.cstr(nOff + 2, 128) : '?');
    }
    return names;
  }

  function parseImports(r, pe, toOff) {
    const out = [];
    let off = pe.dirs[1].rva ? toOff(pe.dirs[1].rva) : -1;
    for (let i = 0; off >= 0 && i < LIMITS.dlls && r.ok(off, 20); i++, off += 20) {
      const oft = r.u32(off), nameRva = r.u32(off + 12), ft = r.u32(off + 16);
      if (!oft && !nameRva && !ft) break;
      const nOff = toOff(nameRva);
      out.push({ dll: nOff >= 0 ? r.cstr(nOff, 128) : '?', funcs: readThunks(r, pe, toOff, oft || ft), delayed: false });
    }
    off = pe.dirs[13].rva ? toOff(pe.dirs[13].rva) : -1;
    for (let i = 0; off >= 0 && i < LIMITS.dlls && r.ok(off, 32); i++, off += 32) {
      const attrs = r.u32(off);
      let nameRva = r.u32(off + 4), intRva = r.u32(off + 16);
      if (!nameRva) break;
      if (!(attrs & 1)) { nameRva -= pe.imageBase; intRva -= pe.imageBase; } // ancient VA-based descriptors
      const nOff = toOff(nameRva);
      out.push({ dll: nOff >= 0 ? r.cstr(nOff, 128) : '?', funcs: readThunks(r, pe, toOff, intRva), delayed: true });
    }
    return out;
  }

  function parseExports(r, toOff, dir) {
    const off = dir.rva ? toOff(dir.rva) : -1;
    if (off < 0 || !r.ok(off, 40)) return null;
    const nameOff = toOff(r.u32(off + 12));
    const nNames = Math.min(r.u32(off + 24), LIMITS.exports);
    const namesOff = toOff(r.u32(off + 32));
    const names = [];
    for (let i = 0; namesOff >= 0 && i < nNames; i++) {
      const o = toOff(r.u32(namesOff + i * 4));
      if (o >= 0) names.push(r.cstr(o, 128));
    }
    return { dllName: nameOff >= 0 ? r.cstr(nameOff, 128) : '', count: r.u32(off + 20), names };
  }

  function parseResources(r, toOff, dir) {
    const out = [];
    const base = dir.rva ? toOff(dir.rva) : -1;
    if (base < 0) return out;
    const seen = new Set();
    const walk = (dirOff, depth, path) => {
      if (depth > 2 || seen.has(dirOff) || !r.ok(dirOff, 16)) return;
      seen.add(dirOff);
      const n = r.u16(dirOff + 12) + r.u16(dirOff + 14);
      for (let i = 0; i < n && out.length < LIMITS.resources; i++) {
        const e = dirOff + 16 + i * 8;
        if (!r.ok(e, 8)) return;
        const nameField = r.u32(e), target = r.u32(e + 4);
        const id = nameField & 0x80000000
          ? r.wstr(base + (nameField & 0x7fffffff) + 2, Math.min(r.u16(base + (nameField & 0x7fffffff)), 128))
          : nameField;
        const p = path.concat([id]);
        if (target & 0x80000000) {
          walk(base + (target & 0x7fffffff), depth + 1, p);
        } else if (r.ok(base + target, 16)) {
          const rva = r.u32(base + target), size = r.u32(base + target + 4);
          out.push({ type: p[0], name: p[1], lang: p[2], rva, size, offset: toOff(rva) });
        }
      }
    };
    walk(base, 0, []);
    return out;
  }

  // VS_VERSIONINFO -> StringFileInfo -> StringTable -> String. Blocks are 32-bit aligned.
  function parseVersionInfo(r, resources) {
    const ent = resources.find((x) => x.type === 16 && x.offset >= 0);
    if (!ent) return null;
    const start = ent.offset, end = Math.min(start + ent.size, r.len);
    const info = {};
    const align = (p) => start + ((p - start + 3) & ~3);
    const block = (off, limit, depth) => {
      if (depth > 3 || !r.ok(off, 6)) return;
      const len = r.u16(off), valLen = r.u16(off + 2), type = r.u16(off + 4);
      if (len < 6) return;
      const blockEnd = Math.min(off + len, limit);
      let p = off + 6, key = '';
      while (p + 1 < blockEnd) { const c = r.u16(p); p += 2; if (!c) break; key += String.fromCharCode(c); }
      p = align(p);
      if (depth === 0 && r.u32(p) === 0xfeef04bd) {
        const ms = r.u32(p + 8), ls = r.u32(p + 12);
        info.fixedVersion = `${ms >>> 16}.${ms & 0xffff}.${ls >>> 16}.${ls & 0xffff}`;
      }
      if (depth === 3) {
        if (type === 1 && valLen && !(key in info)) info[key] = r.wstr(p, valLen).trim();
        return;
      }
      if (depth === 1 && key !== 'StringFileInfo') return;
      let child = align(p + (type === 1 ? valLen * 2 : valLen));
      for (let guard = 0; child + 6 <= blockEnd && guard < 256; guard++) {
        const cl = r.u16(child);
        if (cl < 6) break;
        block(child, blockEnd, depth + 1);
        child = align(child + cl);
      }
    };
    block(start, end, 0);
    return Object.keys(info).length ? info : null;
  }

  function parseManifest(r, resources) {
    const ent = resources.find((x) => x.type === 24 && x.offset >= 0);
    if (!ent) return null;
    const text = new TextDecoder('utf-8').decode(r.u8.subarray(ent.offset, Math.min(ent.offset + ent.size, r.len, ent.offset + 65536)));
    return {
      level: (text.match(/requestedExecutionLevel[^>]*level\s*=\s*["']([^"']+)/i) || [])[1] || null,
      uiAccess: /uiAccess\s*=\s*["']true/i.test(text),
    };
  }

  function parseDebug(r, toOff, dir) {
    const out = { pdb: null, repro: false };
    const off = dir.rva ? toOff(dir.rva) : -1;
    if (off < 0) return out;
    for (let i = 0; i < Math.min(Math.floor(dir.size / 28), 32); i++) {
      const e = off + i * 28;
      const type = r.u32(e + 12), size = r.u32(e + 16), ptr = r.u32(e + 24);
      if (type === 16) out.repro = true;
      if (type === 2 && size > 24 && r.u32(ptr) === 0x53445352) out.pdb = r.utf8z(ptr + 24, Math.min(size - 24, 520)); // "RSDS"
    }
    return out;
  }

  // ---- Authenticode: just enough DER to name the signer and find the signed file digest ----

  function der(u8, off, end) {
    if (off + 2 > end) return null;
    const tag = u8[off];
    let p = off + 1, len = u8[p++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (!n || n > 4 || p + n > end) return null;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + u8[p++];
    }
    if (p + len > end) return null;
    return { tag, start: p, end: p + len };
  }
  function kids(u8, node) {
    const out = [];
    for (let p = node.start; p < node.end && out.length < 512;) {
      const c = der(u8, p, node.end);
      if (!c) break;
      out.push(c);
      p = c.end;
    }
    return out;
  }
  const hex = (u8, n) => Array.from(u8.subarray(n.start, n.end), (b) => b.toString(16).padStart(2, '0')).join('');

  function derString(u8, n) {
    const b = u8.subarray(n.start, n.end);
    if (n.tag === 0x1e) { // BMPString is UTF-16BE
      let s = '';
      for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
      return s;
    }
    return new TextDecoder('utf-8').decode(b);
  }

  function nameAttrs(u8, nameNode) {
    const out = {};
    for (const set of kids(u8, nameNode)) {
      for (const atv of kids(u8, set)) {
        const [oid, val] = kids(u8, atv);
        if (!oid || !val) continue;
        const id = hex(u8, oid);
        const key = id === '550403' ? 'CN' : id === '55040a' ? 'O' : null;
        if (key && !out[key]) out[key] = derString(u8, val);
      }
    }
    return out;
  }

  const DIGESTS = {
    '2b0e03021a': 'SHA-1', '608648016503040201': 'SHA-256', '608648016503040202': 'SHA-384', '608648016503040203': 'SHA-512',
  };

  function parsePkcs7(u8, off, end) {
    const contentInfo = der(u8, off, end);
    const signedData = kids(u8, kids(u8, contentInfo)[1])[0];
    const parts = kids(u8, signedData);
    const out = {};

    // SpcIndirectDataContent holds the digest of the file as it was when signed.
    const indirect = kids(u8, kids(u8, parts[2])[1])[0];
    const digestInfo = kids(u8, indirect)[1];
    const [algId, digest] = kids(u8, digestInfo);
    out.digestAlg = DIGESTS[hex(u8, kids(u8, algId)[0])] || null;
    out.digest = hex(u8, digest);

    const certSet = parts.find((n) => n.tag === 0xa0);
    const certs = certSet ? kids(u8, certSet).filter((c) => c.tag === 0x30).map((c) => {
      const tbs = kids(u8, kids(u8, c)[0]);
      const i = tbs[0] && tbs[0].tag === 0xa0 ? 1 : 0; // skip the optional [0] version
      return { serial: hex(u8, tbs[i]), issuer: nameAttrs(u8, tbs[i + 2]), subject: nameAttrs(u8, tbs[i + 4]) };
    }) : [];
    const signerInfos = parts[parts.length - 1];
    const issuerAndSerial = kids(u8, kids(u8, kids(u8, signerInfos)[0])[1]);
    const serial = issuerAndSerial[1] ? hex(u8, issuerAndSerial[1]) : '';
    const cert = certs.find((c) => c.serial === serial) || certs[0];
    if (cert) {
      out.signer = cert.subject.CN || cert.subject.O || null;
      out.org = cert.subject.O || null;
      out.issuer = cert.issuer.CN || cert.issuer.O || null;
    }
    return out;
  }

  function parseSignature(r, dir) {
    if (!dir.rva || !dir.size) return { present: false };
    const off = dir.rva; // for this directory the "RVA" is a plain file offset
    const sig = { present: true, offset: off, size: dir.size, signer: null };
    if (!r.ok(off, 8) || r.u16(off + 6) !== 2) return sig; // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    try {
      Object.assign(sig, parsePkcs7(r.u8, off + 8, Math.min(off + r.u32(off), r.len)));
    } catch (e) {
      sig.malformed = true;
    }
    return sig;
  }

  // Recomputes the Authenticode image hash: the whole file minus the checksum field,
  // the security directory entry and the signature blob itself.
  async function verifyImageHash(buf, pe) {
    const sig = pe.signature;
    if (!sig || !sig.digest || !sig.digestAlg || !crypto.subtle) return null;
    const u8 = new Uint8Array(buf);
    const ranges = [
      [0, pe.checksumOffset],
      [pe.checksumOffset + 4, pe.securityDirOffset],
      [pe.securityDirOffset + 8, sig.offset],
      [sig.offset + sig.size, u8.length],
    ].filter(([a, b]) => b > a);
    const total = ranges.reduce((n, [a, b]) => n + (b - a), 0);
    const data = new Uint8Array(total);
    let p = 0;
    for (const [a, b] of ranges) { data.set(u8.subarray(a, b), p); p += b - a; }
    const hash = new Uint8Array(await crypto.subtle.digest(sig.digestAlg, data));
    const got = Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('');
    return got === sig.digest;
  }

  root.PEek = root.PEek || {};
  root.PEek.pe = { parse, entropy, verifyImageHash, MACHINES, SUBSYSTEMS };
})(typeof window !== 'undefined' ? window : globalThis);
