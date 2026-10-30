/*
 * PEek — sigscan.js
 * Byte-pattern signature scanner, the classic antivirus technique. It matches compiled code, so it
 * still works when a file's readable text is hidden. Patterns look like: 8B45??[2-4]33C0
 *   ??     any byte
 *   [2-4]  a gap of 2 to 4 bytes
 *
 * To stay fast, each pattern is indexed by a run of plain bytes (its "anchor"). A single pass over the
 * file checks every position against a bitmap of anchor prefixes, and only real candidates get the
 * full comparison. Anchors made of common filler bytes are refused, because they would match everywhere.
 */
(function (root) {
  'use strict';

  const WILD = -1;
  const MIN_ANCHOR = 4;
  const MAX_GAP_TRIES = 65;

  function parse(text) {
    const segments = [];
    let bytes = [];
    let gapBefore = [0, 0];
    for (const m of text.matchAll(/\[(\d+)(?:-(\d+))?\]|\?\?|[0-9A-F]{2}/g)) {
      if (m[1] !== undefined) {
        if (bytes.length) segments.push({ bytes, gap: gapBefore });
        bytes = [];
        gapBefore = [Number(m[1]), Number(m[2] === undefined ? m[1] : m[2])];
      } else {
        bytes.push(m[0] === '??' ? WILD : parseInt(m[0], 16));
      }
    }
    if (bytes.length) segments.push({ bytes, gap: gapBefore });
    return segments;
  }

  // Longest run of plain bytes that is varied enough to be worth indexing.
  function findAnchor(segments) {
    let best = null;
    segments.forEach((seg, index) => {
      let start = 0;
      for (let i = 0; i <= seg.bytes.length; i++) {
        if (i < seg.bytes.length && seg.bytes[i] !== WILD) continue;
        const run = seg.bytes.slice(start, i);
        if (run.length >= MIN_ANCHOR && new Set(run.slice(0, 3)).size >= 2 && (!best || run.length > best.length)) {
          best = { index, offset: start, length: run.length };
        }
        start = i + 1;
      }
    });
    return best;
  }

  function matchAt(u8, pos, bytes) {
    if (pos < 0 || pos + bytes.length > u8.length) return false;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== WILD && u8[pos + i] !== bytes[i]) return false;
    }
    return true;
  }

  function forward(u8, segments, index, pos) {
    if (index >= segments.length) return true;
    const [min, max] = segments[index].gap;
    for (let gap = min; gap <= max && gap - min < MAX_GAP_TRIES; gap++) {
      if (matchAt(u8, pos + gap, segments[index].bytes) && forward(u8, segments, index + 1, pos + gap + segments[index].bytes.length)) return true;
    }
    return false;
  }

  function backward(u8, segments, index, pos) {
    if (index < 0) return true;
    const [min, max] = segments[index + 1].gap;
    const seg = segments[index];
    for (let gap = min; gap <= max && gap - min < MAX_GAP_TRIES; gap++) {
      const start = pos - gap - seg.bytes.length;
      if (matchAt(u8, start, seg.bytes) && backward(u8, segments, index - 1, start)) return true;
    }
    return false;
  }

  function verify(u8, p, hit) {
    const anchorSeg = p.segments[p.anchor.index];
    const start = hit - p.anchor.offset;
    return matchAt(u8, start, anchorSeg.bytes)
      && forward(u8, p.segments, p.anchor.index + 1, start + anchorSeg.bytes.length)
      && backward(u8, p.segments, p.anchor.index - 1, start);
  }

  let compiled = null;

  function compile() {
    const bitmap = new Uint32Array(1 << 19);    // one bit for every possible 3-byte prefix
    const index = new Map();
    const rules = (root.PEek.signatureData || []).map((rule) => ({ family: rule.family, need: rule.need, patterns: [] }));
    rules.forEach((rule, r) => {
      root.PEek.signatureData[r].patterns.forEach((text) => {
        const segments = parse(text);
        const anchor = findAnchor(segments);
        if (!anchor) return;
        const b = segments[anchor.index].bytes.slice(anchor.offset, anchor.offset + anchor.length);
        const pattern = { rule, segments, anchor, tail: b };
        rule.patterns.push(pattern);
        const key = (b[0] << 16) | (b[1] << 8) | b[2];
        bitmap[key >>> 5] |= 1 << (key & 31);
        if (!index.has(key)) index.set(key, []);
        index.get(key).push(pattern);
      });
    });
    compiled = { bitmap, index, rules };
  }

  // Returns [{ family, matched, need }] for each signature whose condition is met.
  function scan(u8) {
    if (!compiled) compile();
    const { bitmap, index, rules } = compiled;
    const found = new Map();
    const end = u8.length - 2;
    for (let i = 0; i < end; i++) {
      const key = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
      if (!(bitmap[key >>> 5] & (1 << (key & 31)))) continue;
      for (const p of index.get(key) || []) {
        if (found.get(p.rule) && found.get(p.rule).has(p)) continue;
        if (p.rule.patterns.length < p.rule.need) continue;
        if (verify(u8, p, i)) {
          if (!found.has(p.rule)) found.set(p.rule, new Set());
          found.get(p.rule).add(p);
        }
      }
    }
    const hits = [];
    for (const [rule, set] of found) {
      if (set.size >= rule.need) hits.push({ family: rule.family, matched: set.size, need: rule.need });
    }
    return hits;
  }

  root.PEek = root.PEek || {};
  root.PEek.sigscan = { scan, parse };
})(typeof window !== 'undefined' ? window : globalThis);
