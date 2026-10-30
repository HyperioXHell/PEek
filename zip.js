/*
 * PEek — zip.js
 * Opens .zip files in memory, using the browser's built-in decompression. Archives are untrusted:
 * sizes stored in the file can lie, so limits are enforced on the bytes actually produced, which
 * stops zip bombs. Nothing is written to disk or run.
 */
(function (root) {
  'use strict';

  const MAX_ENTRIES = 200;
  const MAX_FILE = 256 * 1024 * 1024;
  const MAX_TOTAL = 1024 * 1024 * 1024;

  const EOCD = 0x06054b50, CENTRAL = 0x02014b50, LOCAL = 0x04034b50;

  function findEnd(dv) {
    const stop = Math.max(0, dv.byteLength - 65557);
    for (let i = dv.byteLength - 22; i >= stop; i--) {
      if (dv.getUint32(i, true) === EOCD) return i;
    }
    return -1;
  }

  async function inflate(data, budget) {
    const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > budget) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(size);
    let p = 0;
    for (const c of chunks) { out.set(c, p); p += c.length; }
    return out;
  }

  // Returns { files: [{ name, buffer }], skipped: [{ name, why }] }.
  async function extract(buf, onProgress) {
    const dv = new DataView(buf);
    const u8 = new Uint8Array(buf);
    const end = buf.byteLength >= 22 ? findEnd(dv) : -1;
    if (end < 0) throw new Error('Not a readable ZIP file');
    const count = dv.getUint16(end + 10, true);
    let p = dv.getUint32(end + 16, true);
    if (count === 0xffff || p === 0xffffffff) throw new Error('This ZIP uses a format PEek cannot open yet');

    const files = [], skipped = [];
    const names = new TextDecoder('utf-8');
    let total = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > buf.byteLength || dv.getUint32(p, true) !== CENTRAL) break;
      const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true);
      const compSize = dv.getUint32(p + 20, true), size = dv.getUint32(p + 24, true);
      const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
      const local = dv.getUint32(p + 42, true);
      const name = names.decode(u8.subarray(p + 46, Math.min(p + 46 + nameLen, buf.byteLength)));
      p += 46 + nameLen + extraLen + commentLen;

      if (name.endsWith('/')) continue;
      const skip = (why) => skipped.push({ name, why });
      if (files.length >= MAX_ENTRIES) { skip('Too many files in this archive'); continue; }
      if (flags & 1) { skip('Password protected'); continue; }
      if (method !== 0 && method !== 8) { skip('Unsupported compression'); continue; }
      if (size > MAX_FILE) { skip('Too large'); continue; }
      if (local + 30 > buf.byteLength || dv.getUint32(local, true) !== LOCAL) { skip('Damaged entry'); continue; }
      const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
      if (start + compSize > buf.byteLength) { skip('Damaged entry'); continue; }

      const budget = Math.min(MAX_FILE, MAX_TOTAL - total);
      const data = u8.subarray(start, start + compSize);
      let out;
      try {
        out = method === 8 ? await inflate(data, budget) : (data.length <= budget ? data.slice() : null);
      } catch (e) {
        skip('Damaged entry');
        continue;
      }
      if (!out) { skip('Expands to too much data'); continue; }
      if (!out.length) { skip('Empty file'); continue; }
      total += out.length;
      files.push({ name, buffer: out.buffer });
      if (onProgress) onProgress(name);
    }
    return { files, skipped };
  }

  root.PEek = root.PEek || {};
  root.PEek.zip = { extract, MAX_ENTRIES, MAX_FILE, MAX_TOTAL };
})(typeof window !== 'undefined' ? window : globalThis);
