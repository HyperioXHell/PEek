/*
 * PEek — hidden.js
 * Hunts for dangerous text that a file has lightly disguised. Instead of guessing keys, it knows what
 * it is looking for: each needle is turned into every disguised form up front, so one pass over the
 * file finds them all.
 *   XOR with one byte, added or subtracted bytes  the needle is listed under all 255 keys
 *   XOR with a repeating key                      XORing a file against itself shifted by the key
 *                                                 length cancels the key out, leaving a value that
 *                                                 depends only on the text, so no key is needed
 *   ROT13, reversed text, hex text                checked against the extracted strings
 * It reads and reports text only. Nothing found here is ever run.
 */
(function (root) {
  'use strict';

  const NEEDLES = [
    'vssadmin', 'delete shadows', 'powershell', 'cmd.exe /c', 'http://', 'https://', 'your files', 'encrypted',
    'discord.com/api', 'wscript.shell', 'virtualalloc', 'createremotethread', 'writeprocessmemory', 'getprocaddress',
    'loadlibrary', 'schtasks', 'stratum+tcp', 'this program cannot be run',
  ];
  const KEY_LENGTHS = [2, 3, 4, 8];
  const MAX_SCAN = 64 * 1024 * 1024;
  const MAX_FOUND = 20;
  const MAX_TEXT = 400;

  const printable = (b) => (b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13;
  const prefix = (b) => (b[0] << 16) | (b[1] << 8) | b[2];

  function makeIndex() {
    return { bitmap: new Uint32Array(1 << 19), map: new Map() };
  }

  function addTo(index, key, entry) {
    index.bitmap[key >>> 5] |= 1 << (key & 31);
    if (!index.map.has(key)) index.map.set(key, []);
    index.map.get(key).push(entry);
  }

  let tables = null;

  function build() {
    const fixed = makeIndex();
    const repeat = KEY_LENGTHS.map(() => makeIndex());
    for (const needle of NEEDLES) {
      const n = Array.from(needle, (c) => c.charCodeAt(0));
      for (let k = 1; k < 256; k++) {
        const xor = n.map((b) => b ^ k);
        addTo(fixed, prefix(xor), { bytes: xor, decode: (b) => b ^ k, method: `XOR with key 0x${k.toString(16).toUpperCase().padStart(2, '0')}` });
        const add = n.map((b) => (b + k) & 255);
        addTo(fixed, prefix(add), { bytes: add, decode: (b) => (b - k) & 255, method: `Bytes shifted by ${k}` });
      }
      KEY_LENGTHS.forEach((period, p) => {
        const diff = [];
        for (let i = 0; i + period < n.length; i++) diff.push(n[i] ^ n[i + period]);
        if (diff.length >= 5) addTo(repeat[p], prefix(diff), { diff, needle: n, period });
      });
    }
    tables = { fixed, repeat };
  }

  // Walks outward from a match while the decoded bytes stay readable.
  function readAround(u8, start, decodeAt) {
    let a = start, b = start;
    while (a > 0 && start - a < MAX_TEXT && printable(decodeAt(a - 1))) a--;
    while (b < u8.length && b - start < MAX_TEXT && printable(decodeAt(b))) b++;
    let s = '';
    for (let i = a; i < b; i++) s += String.fromCharCode(decodeAt(i));
    return s;
  }

  function scanBytes(input) {
    if (!tables) build();
    const u8 = input.length > MAX_SCAN ? input.subarray(0, MAX_SCAN) : input;
    const found = new Map();
    const note = (method, text) => { if (!found.has(text) && found.size < MAX_FOUND) found.set(text, method); };
    const { fixed, repeat } = tables;

    for (let i = 0; i + 2 < u8.length && found.size < MAX_FOUND; i++) {
      const key = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
      if (!(fixed.bitmap[key >>> 5] & (1 << (key & 31)))) continue;
      for (const e of fixed.map.get(key)) {
        let hit = i + e.bytes.length <= u8.length;
        for (let j = 3; hit && j < e.bytes.length; j++) hit = u8[i + j] === e.bytes[j];
        if (hit) note(e.method, readAround(u8, i, (at) => e.decode(u8[at])));
      }
    }

    KEY_LENGTHS.forEach((period, p) => {
      const { bitmap, map } = repeat[p];
      for (let i = 0; i + period + 2 < u8.length && found.size < MAX_FOUND; i++) {
        const key = ((u8[i] ^ u8[i + period]) << 16) | ((u8[i + 1] ^ u8[i + 1 + period]) << 8) | (u8[i + 2] ^ u8[i + 2 + period]);
        if (!(bitmap[key >>> 5] & (1 << (key & 31)))) continue;
        for (const e of map.get(key)) {
          if (i + e.needle.length > u8.length) continue;
          let hit = true;
          for (let j = 3; hit && j < e.diff.length; j++) hit = (u8[i + j] ^ u8[i + j + period]) === e.diff[j];
          if (!hit) continue;
          const keyBytes = new Array(period);
          for (let j = 0; j < period; j++) keyBytes[(i + j) % period] = u8[i + j] ^ e.needle[j];
          if (keyBytes.every((b) => b === 0) || keyBytes.every((b) => b === keyBytes[0])) continue;   // plain text or a one-byte key
          note(`XOR with a ${period}-byte repeating key`, readAround(u8, i, (at) => u8[at] ^ keyBytes[at % period]));
        }
      }
    });
    return Array.from(found, ([text, method]) => ({ method, text }));
  }

  const rot13 = (s) => s.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  const reverse = (s) => s.split('').reverse().join('');

  function hexToText(hex) {
    if (hex.length % 2) return null;
    let s = '';
    for (let i = 0; i < hex.length; i += 2) {
      const b = parseInt(hex.slice(i, i + 2), 16);
      if (!printable(b)) return null;
      s += String.fromCharCode(b);
    }
    return s;
  }

  const hasNeedle = (s) => { const low = s.toLowerCase(); return NEEDLES.some((n) => low.includes(n)); };

  function scanText(strings) {
    const out = [];
    const seen = new Set();
    const note = (method, text) => { if (!seen.has(text) && out.length < MAX_FOUND) { seen.add(text); out.push({ method, text }); } };
    for (const s of strings) {
      if (s.length < 8 || s.length > 4096 || out.length >= MAX_FOUND) continue;
      if (hasNeedle(s)) continue;
      const rev = reverse(s);
      if (hasNeedle(rev)) note('Reversed text', rev);
      const rot = rot13(s);
      if (hasNeedle(rot)) note('ROT13', rot);
      for (const hex of s.match(/[0-9a-f]{16,}/gi) || []) {
        const text = hexToText(hex);
        if (text && hasNeedle(text)) note('Hex text', text);
      }
    }
    return out;
  }

  root.PEek = root.PEek || {};
  root.PEek.hidden = { scanBytes, scanText, hasNeedle };
})(typeof window !== 'undefined' ? window : globalThis);
