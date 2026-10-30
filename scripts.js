/*
 * PEek — scripts.js
 * Peels common disguises off scripts so the rules can read what is underneath.
 * This only rewrites text with fixed patterns. Nothing is ever evaluated or run: no eval(),
 * no new Function(), and the page's Content-Security-Policy would block them anyway.
 */
(function (root) {
  'use strict';

  const MAX_TEXT = 4 * 1024 * 1024;
  const MAX_JOIN_TEXT = 1024 * 1024;   // string joining is slower, so it is skipped on huge files
  const MAX_INFLATED = 4 * 1024 * 1024;
  const MAX_LAYERS = 6;
  const MAX_CANDIDATES = 100;
  const MIN_JOINS = 3;                 // normal scripts join a few strings, disguises join many

  function toText(u8) {
    if (u8[0] === 0xff && u8[1] === 0xfe) return new TextDecoder('utf-16le').decode(u8.subarray(2, MAX_TEXT));
    if (u8[0] === 0xfe && u8[1] === 0xff) return new TextDecoder('utf-16be').decode(u8.subarray(2, MAX_TEXT));
    return new TextDecoder('utf-8').decode(u8.subarray(0, MAX_TEXT));
  }

  const char = (n) => (n > 0 && n <= 0xffff ? String.fromCharCode(n) : '');
  const parseNum = (s) => parseInt(s, /^0x/i.test(s) ? 16 : 10);
  const fromCodes = (list) => list.split(',').map((s) => char(parseNum(s.trim()))).join('');

  // ---- Batch files ----

  function batchVariables(text) {
    const vars = new Map();
    const re = /^\s*@?set\s+"?([A-Za-z_]\w*)=([^"\r\n]*)"?\s*$/gim;
    let m;
    while ((m = re.exec(text)) && vars.size < 2000) vars.set(m[1].toLowerCase(), m[2]);
    if (!vars.size) return text;
    let out = text;
    for (let pass = 0; pass < 3; pass++) {
      out = out
        .replace(/%([A-Za-z_]\w*):~(-?\d+)(?:,(-?\d+))?%/g, (all, name, a, b) => {
          const value = vars.get(name.toLowerCase());
          if (value === undefined) return all;
          const start = Number(a) < 0 ? Math.max(0, value.length + Number(a)) : Number(a);
          if (b === undefined) return value.slice(start);
          return Number(b) < 0 ? value.slice(start, value.length + Number(b)) : value.slice(start, start + Number(b));
        })
        .replace(/%([A-Za-z_]\w*)%/g, (all, name) => {
          const value = vars.get(name.toLowerCase());
          return value === undefined ? all : value;
        });
    }
    return out;
  }

  // ---- Joined strings: 'Inv'+'oke', "a" & "b" ----

  function joinStrings(text, counter) {
    if (text.length > MAX_JOIN_TEXT) return text;
    const re = /(["'])((?:(?!\1)[^\r\n])*)\1\s*[+&]\s*(["'])((?:(?!\3)[^\r\n])*)\3/g;
    let out = text;
    for (let pass = 0; pass < 30; pass++) {
      let hits = 0;
      const next = out.replace(re, (all, q, a, q2, b) => { hits++; return q + a + b + q; });
      out = next;
      counter.joins += hits;
      if (!hits) break;
    }
    return out;
  }

  const TRANSFORMS = [
    // `counts` says whether a change looks like a disguise. Normal scripts use these features lightly,
    // so the text is always cleaned up, but only disguise-like use is reported.
    { name: 'Caret escapes', batch: true, run: (t) => t.replace(/\^(?=[^\r\n])/g, ''),
      counts: (t) => (t.match(/[a-z]\^[a-z]/gi) || []).length >= 3 },
    { name: 'Batch variables', batch: true, run: batchVariables,
      counts: (t) => /%[a-z_]\w*%%[a-z_]\w*%|%[a-z_]\w*:~-?\d/i.test(t) },
    { name: 'PowerShell backticks', run: (t) => t.replace(/([A-Za-z-])`(?=[ac-eg-mo-qsu-zAC-EG-MO-QSU-Z])/g, '$1') },
    { name: 'Character codes',
      counts: (t) => /ChrW?\(\s*\d+\s*\)\s*[&+]\s*ChrW?\(|\[char\]\s*\(?\s*\w+\s*\)?\s*\+\s*\[char\]|\[char\]\s*\$_|fromCharCode/i.test(t),
      run: (t) => t
      .replace(/\(\s*((?:(?:0x)?[0-9a-f]{1,4}\s*,\s*){3,}(?:0x)?[0-9a-f]{1,4})\s*\)?\s*\|\s*(?:%|foreach(?:-object)?)\s*\{\s*\[char\]\s*\$_\s*\}\s*\)?(?:\s*-join\s*(?:''|""))?/gi, (m, list) => `'${fromCodes(list)}'`)
      .replace(/\[char\]\s*\(?\s*(0x[0-9a-f]{1,4}|\d{1,5})\s*\)?/gi, (m, n) => `'${char(parseNum(n))}'`)
      .replace(/String\.fromCharCode\(\s*((?:(?:0x)?[0-9a-f]{1,4}\s*,?\s*)+)\)/gi, (m, list) => `"${fromCodes(list)}"`)
      .replace(/\bChrW?\(\s*(\d{1,5})\s*([+-])\s*(\d{1,5})\s*\)/gi, (m, a, op, b) => `"${char(op === '+' ? Number(a) + Number(b) : Number(a) - Number(b))}"`)
      .replace(/\bChrW?\(\s*(\d{1,5})\s*\)/gi, (m, n) => `"${char(Number(n))}"`) },
    { name: 'Escape sequences', run: (t) => t
      .replace(/\\x([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\u([0-9a-f]{4})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))) },
    { name: 'Text replacement', run: (t) => t
      .replace(/(["'])((?:(?!\1)[^\r\n])*)\1\s*\.\s*replace\(\s*(["'])((?:(?!\3)[^\r\n])+)\3\s*,\s*(["'])((?:(?!\5)[^\r\n])*)\5\s*\)/gi,
        (m, q, s, q2, from, q3, to) => q + s.split(from).join(to) + q) },
    { name: 'Format strings', run: (t) => t
      .replace(/(["'])((?:\{\d+\})+)\1\s*-f\s*((?:(["'])[^"'\r\n]*\4\s*,?\s*)+)/gi, (m, q, order, args) => {
        const parts = Array.from(args.matchAll(/(["'])([^"'\r\n]*)\1/g), (a) => a[2]);
        return q + order.replace(/\{(\d+)\}/g, (all, i) => (parts[Number(i)] === undefined ? all : parts[Number(i)])) + q;
      }) },
    { name: 'Joined arrays', run: (t) => t
      .replace(/\(\s*((?:(["'])[^"'\r\n]*\2\s*,\s*)+(["'])[^"'\r\n]*\3)\s*\)\s*-join\s*(?:''|"")/gi, (m, list) => `'${Array.from(list.matchAll(/(["'])([^"'\r\n]*)\1/g), (a) => a[2]).join('')}'`)
      .replace(/-join\s*\(\s*((?:(["'])[^"'\r\n]*\2\s*,\s*)+(["'])[^"'\r\n]*\3)\s*\)/gi, (m, list) => `'${Array.from(list.matchAll(/(["'])([^"'\r\n]*)\1/g), (a) => a[2]).join('')}'`)
      .replace(/\[\s*((?:(["'])[^"'\r\n]*\2\s*,\s*)+(["'])[^"'\r\n]*\3)\s*\]\s*\.join\(\s*(?:""|'')\s*\)/g, (m, list) => `"${Array.from(list.matchAll(/(["'])([^"'\r\n]*)\1/g), (a) => a[2]).join('')}"`) },
    { name: 'Text replacement (PowerShell)', run: (t) => t
      .replace(/(["'])((?:(?!\1)[^\r\n])*)\1\s*-replace\s*(["'])((?:(?!\3)[^\r\n])+)\3\s*,\s*(["'])((?:(?!\5)[^\r\n])*)\5/gi,
        (m, q, s, q2, from, q3, to) => (/^[\w ]+$/.test(from) ? q + s.split(from).join(to) + q : m)) },
    { name: 'Hidden iex', run: (t) => t
      .replace(/\$env:comspec\[\s*4\s*,\s*(?:15|24|26)\s*,\s*25\s*\]\s*-join\s*(?:''|"")/gi, 'iex')
      .replace(/\$shellid\[1\]\s*\+\s*\$shellid\[13\]\s*\+\s*['"]x['"]/gi, 'iex')
      .replace(/\$pshome\[(?:4|21)\]\s*\+\s*\$pshome\[(?:30|34)\]\s*\+\s*['"]x['"]/gi, 'iex') },
    { name: 'Reversed text', run: (t) => t
      .replace(/StrReverse\(\s*"([^"\r\n]*)"\s*\)/gi, (m, s) => `"${s.split('').reverse().join('')}"`)
      .replace(/(["'])((?:(?!\1)[^\r\n])*)\1\s*\.split\(\s*(?:""|'')\s*\)\s*\.reverse\(\)\s*\.join\(\s*(?:""|'')\s*\)/g, (m, q, s) => q + s.split('').reverse().join('') + q) },
  ];

  function applyTransforms(text, isBatch, steps) {
    let out = text;
    for (let round = 0; round < 4; round++) {
      const before = out;
      for (const tr of TRANSFORMS) {
        if (tr.batch && !isBatch) continue;
        const next = tr.run(out);
        if (next !== out) {
          if (!tr.counts || tr.counts(out)) steps.add(tr.name);
          out = next;
        }
      }
      const counter = { joins: 0 };
      out = joinStrings(out, counter);
      if (counter.joins >= MIN_JOINS) steps.add('String joining');
      if (out === before) break;
    }
    return out;
  }

  // ---- Base64 and gzip layers ----

  async function gunzip(bytes) {
    const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_INFLATED) { await reader.cancel(); return null; }
      chunks.push(value);
    }
    const out = new Uint8Array(size);
    let p = 0;
    for (const c of chunks) { out.set(c, p); p += c.length; }
    return out;
  }

  function bytesToText(b) {
    if (b.length < 8) return null;
    const wide = b[1] === 0 && b[3] === 0 && b[5] === 0;
    const text = new TextDecoder(wide ? 'utf-16le' : 'utf-8', { fatal: false }).decode(b);
    let good = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13) good++;
    }
    return good / text.length >= 0.95 ? text : null;
  }

  async function decodeCandidate(s) {
    let bin;
    try { bin = atob(s); } catch (e) { return null; }
    let bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    let gz = false;
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      try { bytes = await gunzip(bytes); } catch (e) { return null; }
      if (!bytes) return null;
      gz = true;
    }
    if (bytes[0] === 0x4d && bytes[1] === 0x5a && bytes.length > 64) return { exe: true, gz };
    const text = bytesToText(bytes);
    return text ? { text, gz } : null;
  }

  async function deobfuscate(u8, fileName) {
    const original = toText(u8);
    const isBatch = /\.(bat|cmd)$/i.test(fileName);
    const steps = new Set();
    const layers = [];
    const seen = new Set([original]);
    let embeddedExe = false;
    const queue = [{ text: original, label: null }];

    while (queue.length && layers.length < MAX_LAYERS) {
      const { text, label } = queue.shift();
      const clean = applyTransforms(text, isBatch, steps);
      if (label || clean !== text) layers.push({ label: label || 'Disguises removed', text: clean });
      if (/0x4d\s*,\s*0x5a\s*,\s*0x90/i.test(clean)) embeddedExe = true;

      // Lists of numbers are often bytes: try them as plain text, then through the hidden text hunter.
      for (const list of (clean.match(/(?:\b(?:0x[0-9a-f]{1,2}|\d{1,3})\s*,\s*){7,}(?:0x[0-9a-f]{1,2}|\d{1,3})\b/gi) || []).slice(0, MAX_CANDIDATES)) {
        const bytes = Uint8Array.from(list.split(',').map((n) => parseNum(n.trim()) & 255));
        const plain = bytesToText(bytes);
        for (const found of plain && PEek.hidden.hasNeedle(plain) ? [{ method: 'Number list', text: plain }] : PEek.hidden.scanBytes(bytes)) {
          steps.add('Number lists');
          if (!seen.has(found.text)) { seen.add(found.text); queue.push({ text: found.text, label: `Decoded from a number list (${found.method})` }); }
        }
      }

      const candidates = (clean.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || []).filter((s) => s.length % 4 === 0).slice(0, MAX_CANDIDATES);
      for (const s of candidates) {
        const found = await decodeCandidate(s);
        if (!found) continue;
        steps.add(found.gz ? 'Gzip' : 'Base64');
        if (found.exe) { embeddedExe = true; steps.add('Base64'); continue; }
        if (!seen.has(found.text)) {
          seen.add(found.text);
          queue.push({ text: found.text, label: found.gz ? 'Unpacked from Base64 and gzip' : 'Decoded from Base64' });
        }
      }
    }
    return { steps: Array.from(steps), layers, embeddedExe };
  }

  root.PEek = root.PEek || {};
  root.PEek.scripts = { deobfuscate };
})(typeof window !== 'undefined' ? window : globalThis);
