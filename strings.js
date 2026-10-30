/*
 * PEek — strings.js
 * Pulls readable text out of binary data (ASCII and UTF-16LE, like `strings` / FLOSS static mode)
 * and sorts the interesting bits into indicator buckets.
 */
(function (root) {
  'use strict';

  const MAX_STRINGS = 400000;
  const MAX_LEN = 2048;

  const isPrint = (b) => (b >= 0x20 && b < 0x7f) || b === 0x09;

  function extract(u8, minLen = 5) {
    const out = [];
    let start = -1;
    for (let i = 0; i <= u8.length && out.length < MAX_STRINGS; i++) {
      if (i < u8.length && isPrint(u8[i])) {
        if (start < 0) start = i;
      } else if (start >= 0) {
        if (i - start >= minLen) out.push(latin1(u8, start, Math.min(i, start + MAX_LEN)));
        start = -1;
      }
    }
    // UTF-16LE: printable byte followed by 0x00. Windows APIs and .NET use this heavily.
    for (let parity = 0; parity < 2; parity++) {
      let s = '';
      for (let i = parity; i + 1 < u8.length && out.length < MAX_STRINGS; i += 2) {
        if (u8[i + 1] === 0 && isPrint(u8[i])) {
          if (s.length < MAX_LEN) s += String.fromCharCode(u8[i]);
        } else {
          if (s.length >= minLen) out.push(s);
          s = '';
        }
      }
      if (s.length >= minLen) out.push(s);
    }
    return out;
  }

  function latin1(u8, a, b) {
    let s = '';
    for (let i = a; i < b; i += 4096) s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(b, i + 4096)));
    return s;
  }

  // ---- Indicators ----

  const RE = {
    url: /\b(?:https?|ftp|wss?):\/\/[a-z0-9][^\s"'<>\\^`{|}]{3,}/gi,
    ip: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{2,5})?\b/g,
    registry: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU)\\[^\s"*?<>|]{3,}|\bSoftware\\(?:Microsoft|Classes|Policies|WOW6432Node)\\[^\s"*?<>|]{3,}/gi,
    path: /(?:\b[a-z]:\\|%[a-z_]+%\\|\\\\\?\\)[^\s"*?<>|]{3,}/gi,
    email: /\b[a-z0-9._%+-]{2,}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,10}\b/gi,
    onion: /\b[a-z2-7]{56}\.onion\b|\b[a-z2-7]{16}\.onion\b/gi,
    btc: /\bbc1[02-9ac-hj-np-z]{38,58}\b/g,
    eth: /\b0x[a-fA-F0-9]{40}\b/g,
    telegramToken: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
  };

  // A cheap substring every match must contain, so most strings skip the regex entirely.
  const HINT = {
    url: '://', ip: '.', registry: '\\', path: '\\', email: '@', onion: '.onion', btc: 'bc1', eth: '0x', telegramToken: ':AA',
  };

  const LIMIT_PER_KIND = 250;

  function isNoiseIp(ip) {
    const [a, b, c, d] = ip.split(':')[0].split('.').map(Number);
    if (a === 0 || a === 127 || a >= 224) return true;                 // unspecified, loopback, multicast/reserved
    if (a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b < 32)) return true; // private LAN
    if (a === 169 && b === 254) return true;                           // link-local
    if (a === 255 || d === 255 || (a <= 30 && b <= 30 && c <= 30 && d <= 30)) return true; // masks and version numbers like 1.2.3.4
    return false;
  }

  // Strings like "%s\\%s" or bare drive letters are format noise, not real paths.
  const isNoisePath = (p) => /%[sdx]|\*\.\*$/i.test(p) || p.length < 6;

  function indicators(strings) {
    const buckets = {};
    for (const k of Object.keys(RE)) buckets[k] = new Set();
    for (const s of strings) {
      if (s.length < 6) continue;
      for (const [kind, re] of Object.entries(RE)) {
        if (buckets[kind].size >= LIMIT_PER_KIND || !s.includes(HINT[kind])) continue;
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(s)) && buckets[kind].size < LIMIT_PER_KIND) {
          let v = m[0].replace(/[.,;:)\]]+$/, '');
          if (kind === 'ip' && isNoiseIp(v)) continue;
          if (kind === 'path' && isNoisePath(v)) continue;
          if (kind === 'email' && /\.(png|jpg|gif|dll|exe|pdb|cpp|h)$/i.test(v)) continue;
          buckets[kind].add(v);
        }
      }
    }
    const out = {};
    for (const [k, set] of Object.entries(buckets)) out[k] = Array.from(set);
    return out;
  }

  root.PEek = root.PEek || {};
  root.PEek.strings = { extract, indicators };
})(typeof window !== 'undefined' ? window : globalThis);
