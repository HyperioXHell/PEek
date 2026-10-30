/*
 * PEek — analyze.js
 * Runs the pipeline on a file and produces one plain report object:
 *   parse -> extract strings -> build features -> detect toolchain -> run rules -> score
 * Nothing here executes the file or sends it anywhere.
 */
(function (root) {
  'use strict';

  const WEIGHT = { high: 30, medium: 14, low: 5, info: 0 };
  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  const LOW_CAP = 15;                    // many small things should not add up to "dangerous"
  const MAX_HAY = 64 * 1024 * 1024;      // characters of text kept for rule matching
  const MAX_UI_STRINGS = 20000;
  const IDENT = /^[A-Za-z_][A-Za-z0-9_]{3,63}$/;
  const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
  const MAX_DECODED = 500;
  const MAX_LAYER_TEXT = 100000;         // characters of each decoded layer shown in the report

  const SCRIPTS = {
    ps1: 'PowerShell script', psm1: 'PowerShell module', bat: 'Batch script', cmd: 'Batch script', vbs: 'VBScript', vbe: 'Encoded VBScript',
    js: 'JavaScript file', jse: 'Encoded JScript', wsf: 'Windows Script File', hta: 'HTML Application', py: 'Python script', sh: 'Shell script',
  };

  const normalizeApi = (name) => name.replace(/([a-z0-9])(A|W)$/, '$1').toLowerCase();
  const startsWith = (u8, ...bytes) => bytes.every((b, i) => u8[i] === b);

  function fileType(u8, name, pe) {
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (pe) {
      const bits = pe.is64 ? '64-bit' : '32-bit';
      if (pe.subsystem === 1) return { kind: 'pe', label: `Windows kernel driver (${bits})` };
      return { kind: 'pe', label: pe.isDll ? `Windows library, DLL (${bits})` : `Windows program (${bits})` };
    }
    if (startsWith(u8, 0x7f, 0x45, 0x4c, 0x46)) return { kind: 'other', label: 'Linux program (ELF)' };
    if (startsWith(u8, 0xcf, 0xfa, 0xed, 0xfe) || startsWith(u8, 0xce, 0xfa, 0xed, 0xfe)) return { kind: 'other', label: 'macOS program (Mach-O)' };
    if (startsWith(u8, 0xca, 0xfe, 0xba, 0xbe)) return { kind: 'other', label: ext === 'class' ? 'Java class file' : 'macOS universal program' };
    if (startsWith(u8, 0x50, 0x4b, 0x03, 0x04)) {
      const zip = { apk: 'Android app (APK)', jar: 'Java archive (JAR)', docx: 'Word document', xlsx: 'Excel workbook', pptx: 'PowerPoint file', msix: 'Windows app package', appx: 'Windows app package' };
      return { kind: 'other', label: zip[ext] || 'ZIP archive' };
    }
    if (startsWith(u8, 0xd0, 0xcf, 0x11, 0xe0)) return { kind: 'other', label: ext === 'msi' ? 'Windows installer (MSI)' : 'Office / OLE file' };
    if (startsWith(u8, 0x25, 0x50, 0x44, 0x46)) return { kind: 'other', label: 'PDF document' };
    if (startsWith(u8, 0x52, 0x61, 0x72, 0x21)) return { kind: 'other', label: 'RAR archive' };
    if (startsWith(u8, 0x37, 0x7a, 0xbc, 0xaf)) return { kind: 'other', label: '7-Zip archive' };
    if (startsWith(u8, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x14)) return { kind: 'script', label: 'Windows shortcut (.lnk)' };
    if (startsWith(u8, 0x4d, 0x5a)) return { kind: 'other', label: 'Old DOS program or damaged Windows program' };
    if (SCRIPTS[ext]) return { kind: 'script', label: SCRIPTS[ext] };
    const sample = u8.subarray(0, 4096);
    const printable = sample.reduce((n, b) => n + ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13 ? 1 : 0), 0);
    if (sample.length && printable / sample.length > 0.9) return { kind: 'script', label: 'Text file' };
    return { kind: 'other', label: 'Unknown file type' };
  }

  function compileTime(pe) {
    if (pe.debug.repro) return { date: null, note: 'Reproducible build: no real date stored' };
    if (!pe.timestamp) return { date: null, note: 'Not stored' };
    const d = new Date(pe.timestamp * 1000);
    if (pe.timestamp === 0x2a425e19) return { date: null, note: 'Default Delphi date (not real)' };
    if (d.getTime() > Date.now() + 86400000 || d.getUTCFullYear() < 1995) return { date: null, note: `Looks fake (${d.toISOString().slice(0, 10)})` };
    return { date: d.toISOString().slice(0, 10), note: 'Can be faked' };
  }

  // Malware often hides commands and URLs as Base64, so readable decoded text is scanned too.
  function decodeHidden(strings) {
    const out = [];
    for (const s of strings) {
      if (s.length < 16 || s.length > 4096 || s.length % 4 || !BASE64.test(s)) continue;
      let text;
      try { text = atob(s); } catch (e) { continue; }
      if (text.length >= 8 && /^[\x09\x20-\x7e]+$/.test(text)) out.push(text);
      if (out.length >= MAX_DECODED) break;
    }
    return out;
  }

  function buildFeatures(u8, fileName, pe, type, script) {
    const strings = PEek.strings.extract(u8);
    const kept = [];
    let total = 0;
    for (const s of strings) {
      if (total + s.length + 1 > MAX_HAY) break;
      kept.push(s);
      total += s.length + 1;
    }
    const decoded = decodeHidden(kept);
    kept.push(...decoded);
    if (script) for (const layer of script.layers) kept.push(...layer.text.split(/\r?\n/).filter((l) => l.trim().length >= 5));
    const hidden = PEek.hidden.scanBytes(u8).concat(PEek.hidden.scanText(kept));
    kept.push(...hidden.map((h) => h.text));

    const apis = new Map();
    const add = (n) => { const k = normalizeApi(n); if (!apis.has(k)) apis.set(k, n); };
    const dlls = new Set();
    let importCount = 0;
    if (pe) {
      for (const d of pe.imports) {
        dlls.add(d.dll.toLowerCase());
        for (const fn of d.funcs) { importCount++; add(fn); }
      }
    }
    // .NET P/Invokes, scripts and programs with tiny import tables name their APIs as text.
    if (type.kind === 'script') {
      for (const s of kept) for (const tok of s.split(/[^A-Za-z0-9_]+/)) if (tok.length >= 6) add(tok);
    } else if (pe && (pe.isDotNet || importCount < 40)) {
      kept.forEach((s, i) => {
        if (!IDENT.test(s)) return;
        add(s);
        if (i + 1 < kept.length && IDENT.test(kept[i + 1])) add(s + kept[i + 1]);   // API names split in two
      });
    }

    const hay = kept.join('\n');
    return {
      pe, kind: type.kind, fileName, apis, dlls, importCount, hay, low: hay.toLowerCase(),
      sections: new Set(pe ? pe.sections.map((s) => s.name) : []),
      iocs: PEek.strings.indicators(kept),
      strings: kept, stringCount: strings.length, decoded, hidden,
    };
  }

  function mergeSignatures(families, hits) {
    for (const hit of hits) {
      const evidence = `Byte signature matched (${hit.matched} of ${hit.need} needed patterns)`;
      const existing = families.find((x) => x.name === hit.family);
      if (existing) {
        if (existing.conf !== 'exact') existing.conf = 'signature';
        existing.evidence.push(evidence);
      } else {
        const fam = PEek.families.FAMILIES.find((x) => x.name === hit.family) || {};
        families.push({ name: hit.family, type: fam.type || 'Malware', about: fam.about || '', conf: 'signature', evidence: [evidence] });
      }
    }
  }

  function scoreOf(findings) {
    let base = 0, low = 0;
    for (const f of findings) {
      if (f.sev === 'low') low = Math.min(LOW_CAP, low + WEIGHT.low);
      else base += WEIGHT[f.sev];
    }
    return Math.min(100, base + low);
  }

  const VERDICTS = {
    clean: { label: 'No red flags found', blurb: 'Nothing in this file matched a dangerous pattern. That is a good sign, but not a guarantee.' },
    blind: { label: 'Can\'t see inside this one', blurb: 'Most of this file is packed or protected, so its real behavior is hidden. No verdict either way: only run it if you trust where it came from.' },
    caution: { label: 'A few things worth checking', blurb: 'Nothing clearly malicious, but it can do some things you should be aware of. Check that they make sense for what this program is supposed to be.' },
    suspicious: { label: 'Suspicious', blurb: 'It has behavior commonly found in malware. Do not run it unless you trust the source and know why it needs to do this.' },
    danger: { label: 'Likely dangerous', blurb: 'Several strong signs of malware. Do not run this file. If you already did, disconnect from the internet, change your passwords from another device, and scan your PC.' },
  };

  // Things no legit signed program contains. A signature never softens these.
  const SMOKING_GUNS = new Set(['browser-stealer', 'wallet-stealer', 'discord-stealer', 'telegram-stealer', 'clipper', 'discord-webhook',
    'powershell', 'amsi-bypass', 'fileless', 'memory-loader', 'script-embedded-exe', 'defender-off', 'uac-bypass', 'block-tools', 'kill-av', 'delete-backups', 'ransom-note', 'miner', 'signature-broken', 'fake-extension', 'suspicious-project']);

  function verdictOf(score, findings, blind, signer) {
    const highs = findings.filter((f) => f.sev === 'high').length;
    let level = 'clean';
    if (score >= 60 || highs >= 2) level = 'danger';
    else if (score >= 30 || highs >= 1) level = 'suspicious';
    else if (blind) level = 'blind';
    else if (score >= 12) level = 'caution';

    // Browsers and Windows itself really do have these capabilities. PEek cannot verify a certificate
    // chain and a forged certificate can carry any name, so this hands the final check to Windows
    // instead of calling the file safe.
    if (signer && (level === 'danger' || level === 'suspicious') && !findings.some((f) => SMOKING_GUNS.has(f.id))) {
      return {
        level: 'signed',
        label: `Powerful, but signed by ${signer}`,
        blurb: 'It has abilities malware also uses, and it carries a signature that matches the file. PEek cannot prove the certificate is real, so check it: right-click the file > Properties > Digital Signatures > Details. If Windows says the signature is OK and you recognize the name, this is very likely legitimate.',
      };
    }
    return Object.assign({ level }, VERDICTS[level]);
  }

  const CLASSES = [
    [0, 'Clean'], [2, 'Low risk'], [4, 'Suspicious'], [6, 'Potentially malicious'], [8, 'Malicious'], [10, 'Critical'],
  ];

  // Turns the internal 0-100 score into the 0-10 rating shown to people.
  function ratingOf(score, findings, verdict, floor) {
    const fired = new Set(findings.map((x) => x.id));
    const highs = findings.filter((x) => x.sev === 'high').length;
    let value = Math.max(Math.ceil(score / 10), floor);
    if ([...fired].some((id) => SMOKING_GUNS.has(id))) value = Math.max(value, 5);
    if (verdict.level === 'danger') value = Math.max(value, 7);
    if (highs >= 3) value = Math.max(value, 9);
    if (fired.has('boot-overwrite') || (fired.has('delete-backups') && fired.has('ransom-note'))) value = 10;
    if (verdict.level === 'signed') value = Math.min(value, 4);
    const label = verdict.level === 'signed' ? 'Verify signature'
      : verdict.level === 'blind' ? 'Unable to assess'
        : CLASSES.find(([max]) => value <= max)[1];
    const tone = verdict.level === 'signed' || verdict.level === 'blind' ? verdict.level
      : value <= 2 ? 'clean' : value <= 4 ? 'caution' : value <= 6 ? 'suspicious' : 'danger';
    return { value, label, tone, capped: verdict.level === 'signed' };
  }

  // PEek never runs the file, so a result can only mean "the code for this is present".
  function indicatorsOf(fired, blind) {
    const none = blind ? 'Unknown' : 'Not found';
    const row = (name, detected, possible = []) => ({
      name, result: detected.some((id) => fired.has(id)) ? 'Detected' : possible.some((id) => fired.has(id)) ? 'Possible' : none,
    });
    const network = row('Network activity', ['discord-webhook', 'telegram-bot', 'throwaway-hosts', 'tor'], ['network', 'ip-lookup', 'hardcoded-ips']);
    if (network.result === 'Not found') network.result = 'Not established';
    return [
      row('Disk manipulation', ['raw-disk', 'boot-overwrite'], ['encrypts-files']),
      row('Boot modification', ['boot-overwrite'], ['raw-disk']),
      row('Process interaction', ['injection', 'hollowing', 'memory-access', 'kill-av']),
      row('Desktop manipulation', ['block-tools'], ['screenshot']),
      row('Destructive behavior', ['boot-overwrite', 'bsod', 'delete-backups', 'ransom-note']),
      network,
    ];
  }

  function assessmentOf(markers, rating, verdict) {
    const static_ = 'This comes from static analysis: the file was not run.';
    if (verdict.level === 'blind') return `The file is packed or protected, so its real behavior could not be read. ${static_}`;
    if (!markers.length) return `No strong indicators were found in the parts of the file PEek can read. ${static_}`;
    const names = markers.map((m) => m.replace(/_/g, ' '));
    const list = names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}` : names[0];
    const close = verdict.level === 'signed' ? 'These abilities also exist in legitimate software, and this file carries a matching signature.'
      : rating.value >= 9 ? 'Together these make it an extremely high-risk file.'
        : rating.value >= 7 ? 'Together these make it a high-risk file.'
          : rating.value >= 3 ? 'Check that these make sense for what this program is supposed to be.'
            : 'On their own, these are minor.';
    return `The file shows indicators of ${list}. ${close} ${static_}`;
  }

  function limitsOf(f, detect, type) {
    const out = [];
    const tags = detect.tags;
    if (detect.unknownPacker || tags.some((t) => t.kind === 'packer' || t.kind === 'protector')) {
      out.push('Most of the code is packed or protected, so this report only sees the outer shell. The real behavior may be missing here.');
    }
    if (tags.some((t) => t.kind === 'installer')) {
      out.push('This is an installer. The programs it installs are compressed inside and were not analyzed. Extract them and scan those too.');
    }
    if (detect.tags.some((t) => t.id === 'pyinstaller' || t.id === 'nuitka' || t.id === 'pkg' || t.id === 'electron' || t.id === 'autoit')) {
      out.push('The app\'s real code is bundled in a compressed form, so most of its logic is not visible here. Use the next steps below to extract it.');
    }
    if (type.kind === 'other') {
      out.push('PEek fully understands Windows programs. For this file type it can only scan the readable text inside.');
    }
    return out;
  }

  function summaryOf(type, detect, findings, pe) {
    const parts = [];
    const label = type.label.replace(/^(Text|Unknown|Old)/, (m) => m.toLowerCase());
    let what = `This is ${/^[aeiou]/i.test(label) ? 'an' : 'a'} ${label}`;
    if (detect.language && pe) what += detect.language.startsWith('Native') ? ' (compiler not identified)' : ` built with ${detect.language}`;
    parts.push(`${what}.`);
    const highs = findings.filter((x) => x.sev === 'high').length;
    const meds = findings.filter((x) => x.sev === 'medium').length;
    const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
    if (highs && meds) parts.push(`Found ${plural(highs, 'high-risk behavior')} and ${plural(meds, 'risky one')}.`);
    else if (highs) parts.push(`Found ${plural(highs, 'high-risk behavior')}.`);
    else if (meds) parts.push(`Found ${plural(meds, 'behavior')} worth checking.`);
    return parts.join(' ');
  }

  async function analyze(buf, fileName) {
    const t0 = performance.now();
    const u8 = new Uint8Array(buf);
    const pe = PEek.pe.parse(buf);
    const type = fileType(u8, fileName, pe);
    const script = type.kind === 'script' ? await PEek.scripts.deobfuscate(u8, fileName) : null;
    let dotnet = null;
    if (pe && pe.isDotNet) {
      try { dotnet = PEek.dotnet.parse(buf, pe); } catch (e) { dotnet = null; }
    }
    const f = buildFeatures(u8, fileName, pe, type, script);
    f.script = script;
    f.dotnet = dotnet;
    if (dotnet) {
      for (const p of dotnet.pinvokes) { const k = p.name.replace(/([a-z0-9])(A|W)$/, '$1').toLowerCase(); if (!f.apis.has(k)) f.apis.set(k, p.name); }
      f.netCalls = new Set(dotnet.calls.map((c) => c.toLowerCase()));
    }

    f.signatureValid = null;
    if (pe && pe.signature.digest) {
      try { f.signatureValid = await PEek.pe.verifyImageHash(buf, pe); } catch (e) { f.signatureValid = null; }
    }

    f.detect = PEek.detect(f);
    const findings = PEek.rules.run(f).sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
    const score = scoreOf(findings);
    const blind = f.detect.unknownPacker || f.detect.tags.some((t) => t.kind === 'packer' || t.kind === 'protector');

    let sha256 = null;
    if (root.crypto && crypto.subtle) {
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
      sha256 = Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('');
    }

    const families = PEek.families.match(f, sha256);
    if (pe) mergeSignatures(families, PEek.sigscan.scan(u8));
    const confirmed = families.filter((x) => x.conf !== 'possible');

    // A family match outranks the behavior score, and a signature never softens it.
    let verdict = verdictOf(score, findings, blind, families.length || f.signatureValid !== true ? null : pe.signature.signer);
    if (confirmed.length) verdict = Object.assign({ level: 'danger' }, VERDICTS.danger);
    else if (families.length && verdict.level !== 'danger') verdict = Object.assign({ level: 'suspicious' }, VERDICTS.suspicious);
    const rating = ratingOf(score, findings, verdict, families.length ? (confirmed.length ? 9 : 5) : 0);
    const firedIds = new Set(findings.map((x) => x.id));
    const markers = PEek.tags.classify({ fired: firedIds, families, value: rating.value, signed: f.signatureValid === true && !families.length });
    const assessment = assessmentOf(markers, rating, verdict);
    const named = families.map((x) => `${x.name} (${x.type})`).join(', ');

    const report = {
      fileName, size: u8.length, sha256, type,
      score, verdict, rating, markers, findings, families, hidden: f.hidden, dotnet,
      script: script && script.layers.length ? { steps: script.steps, layers: script.layers.map((l) => ({ label: l.label, text: l.text.slice(0, MAX_LAYER_TEXT) })) } : null,
      indicators: indicatorsOf(firedIds, blind),
      assessment: families.length
        ? `${confirmed.length ? 'Matches a known malware family' : 'Contains markers of a known family'}: ${named}. ${markers.length ? assessment : 'This comes from static analysis: the file was not run.'}`
        : assessment,
      summary: summaryOf(type, f.detect, findings, pe),
      limits: limitsOf(f, f.detect, type),
      detect: f.detect,
      iocs: f.iocs,
      strings: f.strings.slice(0, MAX_UI_STRINGS),
      stringCount: f.stringCount,
      importCount: f.importCount,
      pe: null,
    };

    if (pe) {
      const v = pe.versionInfo || {};
      report.pe = {
        machine: pe.machineName, subsystem: pe.subsystemName, isDll: pe.isDll, isDotNet: pe.isDotNet,
        compiled: compileTime(pe), linker: pe.linkerVersion,
        company: v.CompanyName || null, product: v.ProductName || null, description: v.FileDescription || null,
        version: v.ProductVersion || v.FileVersion || v.fixedVersion || null, originalName: v.OriginalFilename || null,
        signature: {
          present: pe.signature.present, signer: pe.signature.signer, issuer: pe.signature.issuer || null,
          matchesFile: f.signatureValid,
        },
        admin: pe.manifest ? pe.manifest.level : null,
        pdb: pe.debug.pdb,
        hardening: { aslr: pe.aslr, dep: pe.dep, cfg: pe.cfg },
        sections: pe.sections.map((s) => ({ name: s.name, size: s.rawSize, entropy: s.entropy, exec: s.exec, write: s.write })),
        imports: pe.imports.map((d) => ({ dll: d.dll, funcs: d.funcs, delayed: d.delayed })),
        exports: pe.exports,
        overlay: pe.overlay,
        resources: pe.resources.length,
      };
    }

    report.ms = Math.round(performance.now() - t0);
    return report;
  }

  function toMarkdown(r) {
    const lines = [`# ${r.fileName}: Analysis Report`, '', `**${r.rating.label}: ${r.rating.value}/10**`, '', r.summary, ''];
    if (r.families.length) lines.push(`Known family: ${r.families.map((x) => `${x.name} (${x.conf})`).join(', ')}`, '');
    if (r.markers.length) lines.push(`Tags: ${r.markers.join(', ')}`, '');
    lines.push('| Indicator | Result |', '| --- | --- |', ...r.indicators.map((i) => `| ${i.name} | ${i.result} |`), '');
    lines.push('## Analysis verdict', '', r.assessment, '');
    lines.push(`- Type: ${r.type.label}`, `- Size: ${r.size.toLocaleString('en-US')} bytes`, `- SHA-256: \`${r.sha256 || 'n/a'}\``);
    if (r.pe) {
      const sig = r.pe.signature;
      lines.push(`- Built with: ${r.detect.language}`);
      lines.push(`- Signed: ${sig.present ? `${sig.signer || 'unknown'}${sig.matchesFile === false ? ' (DOES NOT MATCH FILE)' : ''}` : 'no embedded signature'}`);
    }
    lines.push('');
    if (r.findings.length) {
      lines.push('## Findings', '');
      for (const f of r.findings) {
        lines.push(`### [${f.sev.toUpperCase()}] ${f.title}${f.attack ? ` (${f.attack})` : ''}`, '', f.why, '', `Evidence: ${f.evidence.map((e) => `\`${e.v}\``).join(', ')}`, '');
      }
    }
    if (r.limits.length) lines.push('## Limits of this report', '', ...r.limits.map((l) => `- ${l}`), '');
    lines.push('_Generated by PEek. Static analysis only: the file was not run. A clean result is not a guarantee._');
    return lines.join('\n');
  }

  root.PEek = root.PEek || {};
  root.PEek.analyze = analyze;
  root.PEek.toMarkdown = toMarkdown;
})(typeof window !== 'undefined' ? window : globalThis);
