/*
 * PEek — app.js
 * The page itself. Text taken from analyzed files is hostile input: it only ever reaches the DOM
 * through text nodes (see h()), never as HTML, and URLs found in a file are never made clickable.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const VIEWS = ['home', 'busy', 'error', 'batch', 'report', 'guide'];
  const MAX_STRING_ROWS = 500;

  function view(name) {
    for (const v of VIEWS) $(v).hidden = v !== name;
    const active = name === 'guide' ? 'guide-link' : 'scan-link';
    for (const id of ['scan-link', 'guide-link']) {
      if (id === active) $(id).setAttribute('aria-current', 'page');
      else $(id).removeAttribute('aria-current');
    }
    window.scrollTo(0, 0);
  }

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'open' || k === 'hidden') el[k] = v;
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid);
    }
    return el;
  }

  function fmtSize(n) {
    if (n < 1024) return `${n} bytes`;
    const units = ['KB', 'MB', 'GB'];
    let v = n, i = -1;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      const ta = h('textarea', { class: 'visually-hidden' }, text);
      document.body.append(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    }
  }

  const flash = (btn, label) => {
    const old = btn.textContent;
    btn.textContent = label;
    setTimeout(() => { btn.textContent = old; }, 1400);
  };

  // ---- Report sections ----

  function threatBox(r) {
    const family = r.families[0];
    const types = r.markers.filter((m) => PEek.tags.TAGS.some((t) => t.tag === m && t.group === 'type'));
    const row = (label, value) => h('div', {}, h('dt', {}, label), h('dd', {}, value));
    return h('dl', { class: 'threat-box' },
      family ? row('Family', family.conf === 'possible' ? `${family.name} (possible)` : family.name) : null,
      row('Type', types.length ? types.slice(0, 2).join(', ') : 'None detected'));
  }

  function generalCard(r) {
    const special = r.verdict.level === 'signed' || r.verdict.level === 'blind';
    const value = r.rating.value;
    const facts = [['Size', fmtSize(r.size)], ['Type', r.type.label]];
    if (r.sha256) facts.push(['SHA-256', r.sha256]);
    const tags = r.families.length + r.markers.length ? h('div', { class: 'tags' },
      r.families.map((x) => h('span', { class: 'tag family' }, x.name)),
      r.markers.map((m) => h('span', { class: 'tag' }, m))) : null;
    return h('div', { class: `hero ${r.rating.tone}`, title: r.rating.capped ? 'Limited to 4/10 because the file carries a matching signature' : null },
      h('div', { class: 'hero-top' },
        h('div', {}, h('p', { class: 'eyebrow' }, 'Threat assessment'), h('h2', {}, special ? r.verdict.label : r.rating.label)),
        h('div', { class: 'hero-side' }, h('p', { class: 'hero-score' }, h('b', {}, String(value)), '/10'), threatBox(r))),
      h('div', { class: 'meter', role: 'img', 'aria-label': `Threat score ${value} out of 10` },
        Array.from({ length: 10 }, (_, i) => h('i', { class: i < value ? 'on' : null }))),
      h('p', { class: 'blurb' }, r.verdict.blurb),
      h('p', { class: 'summary' }, r.summary),
      tags,
      h('dl', { class: 'quick' }, facts.map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, v)))));
  }

  // ---- Malware guide ----

  const STEPS = [
    ['1. It reads the file', 'PEek pulls out the readable text and the list of Windows functions the program uses. The program never runs.'],
    ['2. It checks the rules', 'Each rule looks for a specific combination of clues. A rule only fires when enough of them appear together, because one clue alone usually means nothing.'],
    ['3. It adds up the score', 'Each rule has a severity, and those add up to the score out of 10. A known family match pushes the score higher. A matching signature limits it unless the evidence is clearly malicious.'],
  ];

  function detectionLabel(fam) {
    if (fam.sig) return fam.strings ? 'Detected by byte signatures and text markers' : 'Detected by byte signatures';
    if (fam.strings && fam.hashes) return 'Detected by text markers and exact known files';
    if (fam.hashes) return 'Detected only as exact known files';
    if (fam.strings) return fam.conf === 'possible' ? 'Detected by text markers, possible match at most' : 'Detected by text markers';
    return 'Not detected yet';
  }

  function guideCard(fam) {
    return h('article', { class: 'guide-card' },
      h('div', { class: 'guide-head' }, h('b', {}, fam.name), h('span', { class: 'chip meta' }, fam.type)),
      h('p', {}, fam.about),
      h('p', { class: 'guide-how' }, detectionLabel(fam)));
  }

  function tagCard(t) {
    return h('article', { class: 'guide-card' },
      h('div', { class: 'guide-head' }, h('span', { class: `tag ${t.group === 'type' ? 'family' : ''}` }, t.tag)),
      h('p', {}, t.about),
      h('p', { class: 'guide-how' }, `PEek adds this tag when: ${t.how}`));
  }

  function renderGuide() {
    const { FAMILIES, TYPES } = PEek.families;
    const grid = h('div', { class: 'guide-grid' });
    const status = h('p', { class: 'hint', 'aria-live': 'polite' });
    let type = 'All';
    let query = '';
    const update = () => {
      const q = query.trim().toLowerCase();
      const shown = FAMILIES.filter((f) => (type === 'All' || f.type === type)
        && (!q || `${f.name} ${f.type} ${f.about}`.toLowerCase().includes(q)));
      grid.replaceChildren(...shown.map(guideCard));
      status.textContent = `${shown.length} of ${FAMILIES.length} families`;
      typeLine.textContent = type === 'All' ? '' : TYPES[type];
    };
    const typeLine = h('p', { class: 'guide-type' });
    const types = ['All', ...new Set(FAMILIES.map((f) => f.type))];
    const buttons = types.map((t) => h('button', { type: 'button', class: 'filter', 'aria-pressed': String(t === 'All'), onclick: (e) => {
      type = t;
      buttons.forEach((b) => b.setAttribute('aria-pressed', String(b === e.currentTarget)));
      update();
    } }, t));
    $('guide').replaceChildren(
      h('h2', { class: 'guide-title' }, 'Malware guide'),
      h('p', { class: 'lede' }, 'What PEek looks for, and what each name actually means.'),
      h('div', { class: 'block' }, h('h3', {}, 'How PEek decides'),
        h('div', { class: 'how' }, STEPS.map(([t, d]) => h('div', { class: 'step' }, h('b', {}, t), h('p', {}, d)))),
        h('div', { class: 'step example' }, h('b', {}, 'Example: "Looks like a game cheat"'),
          h('p', {}, 'This rule searches for words cheats tend to contain, such as aimbot, triggerbot, wallhack, and memory offset names like dwEntityList and m_iHealth. If at least two appear, it fires. It goes by what is inside the file, so renaming the file does not change the result. A game modding tool or dumper can trigger it too, so it is a clue and not proof.'))),
      h('div', { class: 'block' }, h('h3', {}, 'Malware types'),
        h('p', { class: 'hint' }, 'What a file is. A file can have several of these.'),
        h('div', { class: 'guide-grid' }, PEek.tags.TAGS.filter((t) => t.group === 'type').map(tagCard))),
      h('div', { class: 'block' }, h('h3', {}, 'Behaviors'),
        h('p', { class: 'hint' }, 'What a file does, whatever type it is.'),
        h('div', { class: 'guide-grid' }, PEek.tags.TAGS.filter((t) => t.group === 'behavior').map(tagCard))),
      h('div', { class: 'block' }, h('h3', {}, 'Known families'),
        h('input', { class: 'search', type: 'search', placeholder: 'Search, for example "wallet" or "kawaii"', 'aria-label': 'Search families', oninput: (e) => { query = e.target.value; update(); } }),
        h('div', { class: 'filters' }, buttons), typeLine, status, grid));
    update();
  }

  function indicatorsBlock(r) {
    const tone = { Detected: 'hit', Possible: 'maybe' };
    return h('div', { class: 'block' }, h('h3', {}, 'Behavioral indicators'),
      h('div', { class: 'indicators' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Indicator'), h('th', {}, 'Result'))),
        h('tbody', {}, r.indicators.map((i) => h('tr', {}, h('td', {}, i.name), h('td', { class: tone[i.result] || 'none' }, i.result)))))));
  }

  function assessmentBlock(r) {
    return h('div', { class: 'block' }, h('h3', {}, 'Analysis verdict'),
      h('p', { class: 'assessment' }, r.assessment),
      h('p', { class: `final ${r.rating.tone}` }, `${r.rating.label} — ${r.rating.value}/10`));
  }

  // ---- AI opinion ----

  const MODEL_KEY = 'peek.ollamaModel';
  const SUGGESTED_MODEL = 'llama3.2';

  const storedModel = () => {
    try { return localStorage.getItem(MODEL_KEY); } catch (e) { return null; }
  };
  const storeModel = (name) => {
    try { localStorage.setItem(MODEL_KEY, name); } catch (e) { /* the choice just isn't remembered */ }
  };

  function ollamaSetup() {
    const local = location.protocol === 'file:';
    const allow = local ? null : `setx OLLAMA_ORIGINS "${location.origin}"`;
    const cmd = (text) => h('div', { class: 'cmd' }, h('code', {}, text),
      h('button', { type: 'button', onclick: async (e) => { const b = e.currentTarget; if (await copyText(text)) flash(b, 'Copied'); } }, 'Copy'));
    return h('div', { class: 'ai-setup' },
      h('p', {}, 'PEek could not reach Ollama on this PC. To set it up:'),
      h('p', {}, '1. Install Ollama from ', h('a', { href: 'https://ollama.com/download', target: '_blank', rel: 'noopener noreferrer' }, 'ollama.com'), ' and keep it running.'),
      h('p', {}, '2. Download a model:'), cmd(`ollama pull ${SUGGESTED_MODEL}`),
      allow ? [h('p', {}, '3. Allow this site to use it, then restart Ollama:'), cmd(allow)]
        : h('p', {}, '3. If this still fails, open PEek from its website. Some browsers block local pages from reaching Ollama.'));
  }

  function aiBlock(r) {
    const status = h('p', { class: 'hint', 'aria-live': 'polite' });
    const panel = h('div');
    const output = h('pre', { class: 'code ai-output', hidden: true });
    let controller = null;

    const run = async (model, button, stop) => {
      storeModel(model);
      controller = new AbortController();
      output.textContent = '';
      output.hidden = false;
      button.disabled = true;
      stop.hidden = false;
      status.textContent = `Asking ${model}. This can take a minute on a normal PC.`;
      try {
        await PEek.ai.analyze(r, model, { signal: controller.signal, onText: (t) => output.append(t) });
        status.textContent = `Finished. This is an AI opinion from ${model}.`;
      } catch (e) {
        status.textContent = e.name === 'AbortError' ? 'Stopped.' : `The AI run failed: ${e.message}`;
      }
      button.disabled = false;
      stop.hidden = true;
    };

    const connect = async () => {
      status.textContent = 'Looking for Ollama on this PC...';
      panel.replaceChildren();
      let models;
      try {
        models = await PEek.ai.listModels();
      } catch (e) {
        status.textContent = '';
        panel.replaceChildren(ollamaSetup());
        return;
      }
      if (!models.length) {
        status.textContent = `Ollama is running but has no models. Run: ollama pull ${SUGGESTED_MODEL}`;
        return;
      }
      status.textContent = '';
      const saved = storedModel();
      const select = h('select', { 'aria-label': 'AI model' }, models.map((m) => h('option', { value: m }, m)));
      if (models.includes(saved)) select.value = saved;
      const stop = h('button', { class: 'btn', type: 'button', hidden: true, onclick: () => controller && controller.abort() }, 'Stop');
      const go = h('button', { class: 'btn primary', type: 'button', onclick: (e) => run(select.value, e.currentTarget, stop) }, 'Run analysis');
      panel.replaceChildren(h('div', { class: 'ai-run' }, select, go, stop));
    };

    return h('div', { class: 'block' }, h('h3', {}, 'AI opinion'),
      h('p', { class: 'hint' }, 'Optional. Uses the findings in this report, never the file itself. AI can be wrong, and it cannot change the score.'),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', type: 'button', onclick: async (e) => { const b = e.currentTarget; if (await copyText(PEek.ai.prompt(r))) flash(b, 'Copied'); } }, 'Copy for AI'),
        h('button', { class: 'btn', type: 'button', onclick: connect }, 'Analyze with local AI')),
      status, panel, output);
  }

  function evidenceChips(evidence) {
    return h('div', { class: 'chips' }, evidence.map((e) =>
      h('span', { class: `chip ${e.t === 'meta' ? 'meta' : ''}` }, e.t === 'text' ? `"${e.v}"` : e.v)));
  }

  function signatureRow(level, title, text, pills, evidence) {
    return h('details', { class: `sig ${level}` },
      h('summary', {}, h('span', { class: 'sig-level' }, level),
        h('div', {}, h('b', {}, title), h('p', {}, text), h('div', { class: 'sig-tags' }, pills))),
      h('div', { class: 'sig-body' }, h('p', {}, 'Evidence found in the file'), evidenceChips(evidence)));
  }

  function signaturesBlock(r) {
    const labels = { exact: 'Exact file match', signature: 'Byte signature match', strong: 'Strong match', possible: 'Possible match' };
    const families = r.families.map((x) => signatureRow(x.conf === 'possible' ? 'medium' : 'high', `Family: ${x.name}`, `${labels[x.conf]}. ${x.about}`,
      [h('span', { class: 'tag family' }, x.name), h('span', { class: 'tag' }, x.type)],
      x.evidence.map((v) => ({ t: 'meta', v }))));
    const findings = r.findings.map((f) => signatureRow(f.sev, f.title, f.why, [
      h('span', { class: 'tag' }, f.cat),
      f.attack ? h('a', { class: 'tag attack', href: `https://attack.mitre.org/techniques/${f.attack.replace('.', '/')}/`, target: '_blank', rel: 'noopener noreferrer', title: 'Open this technique on MITRE ATT&CK' }, f.attack) : null,
    ], f.evidence));
    const rows = families.concat(findings);
    return h('div', { class: 'block' }, h('h3', {}, 'What it can do'),
      rows.length ? rows : h('p', { class: 'empty' }, 'No risky behavior matched.'));
  }

  function signatureFact(sig) {
    if (!sig.present) {
      return ['No embedded signature', h('span', { class: 'sub' }, 'Files that ship with Windows are often signed separately, so this alone is not a red flag.')];
    }
    const name = sig.signer || 'unknown signer';
    if (sig.matchesFile === false) {
      return [h('span', { class: 'bad' }, `Claims ${name}, but the signature does not match this file`)];
    }
    const checked = sig.matchesFile ? 'The file has not been changed since signing.' : 'Could not compare it with the file.';
    return [
      h('span', { class: sig.matchesFile ? 'ok' : '' }, `Signed by ${name}`),
      h('span', { class: 'sub' }, `${checked} PEek cannot confirm the certificate is trusted: check Properties > Digital Signatures in Windows.`),
    ];
  }

  function factsBlock(r) {
    const rows = [['Type', r.type.label], ['Size', `${fmtSize(r.size)} (${r.size.toLocaleString('en-US')} bytes)`]];
    if (r.pe) {
      const p = r.pe;
      const others = r.detect.tags.filter((t) => t.kind !== 'language').map((t) => t.name);
      rows.push(['Built with', [r.detect.language, others.length ? h('span', { class: 'sub' }, others.join(', ')) : null]]);
      if (p.description || p.product || p.company) {
        const label = p.description || p.product;
        rows.push(['Claims to be', [label || p.company, label && p.company ? h('span', { class: 'sub' }, `by ${p.company}`) : null]]);
      }
      if (p.version) rows.push(['Version', p.version]);
      if (p.originalName && p.originalName.toLowerCase() !== r.fileName.toLowerCase()) rows.push(['Original file name', p.originalName]);
      rows.push(['Signature', signatureFact(p.signature)]);
      rows.push(['Compiled', [p.compiled.date || p.compiled.note, p.compiled.date ? h('span', { class: 'sub' }, p.compiled.note) : null]]);
      if (p.admin && p.admin !== 'asInvoker') rows.push(['Admin rights', p.admin === 'requireAdministrator' ? 'Always asks for them' : p.admin]);
      if (p.pdb) rows.push(['Developer path', h('span', { class: 'mono' }, p.pdb)]);
    }
    if (r.sha256) {
      rows.push(['SHA-256', [
        h('span', { class: 'mono' }, r.sha256),
        h('span', { class: 'sub' }, h('a', { href: `https://www.virustotal.com/gui/file/${r.sha256}`, target: '_blank', rel: 'noopener noreferrer' }, 'Look up on VirusTotal'), ' (opens their site and sends only this hash, not the file)'),
      ]]);
    }
    return h('div', { class: 'block' }, h('h3', {}, 'About this file'),
      h('dl', { class: 'facts' }, rows.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])));
  }

  function nextStepsBlock(r) {
    if (!r.detect.next.length) return null;
    const quoted = /\s/.test(r.fileName) ? `"${r.fileName}"` : r.fileName;
    const steps = r.detect.next.map((s) => {
      const cmd = s.cmd ? s.cmd.replace(/\bFILE\b/g, quoted) : null;
      return h('div', { class: 'step' }, h('b', {}, s.title), h('p', {}, s.how),
        cmd ? h('div', { class: 'cmd' }, h('code', {}, cmd),
          h('button', { type: 'button', onclick: async (e) => { const b = e.currentTarget; if (await copyText(cmd)) flash(b, 'Copied'); } }, 'Copy')) : null);
    });
    return h('div', { class: 'block' }, h('h3', {}, 'Next steps for reverse engineers'), steps);
  }

  function listPanel(title, items) {
    if (!items.length) return null;
    return h('details', { class: 'panel' },
      h('summary', {}, title, h('span', { class: 'count' }, String(items.length))),
      h('div', { class: 'inner' }, h('ul', { class: 'list' }, items.map((x) => h('li', {}, x)))));
  }

  function foundInsideBlock(r) {
    const i = r.iocs;
    const panels = [
      listPanel('Hidden text decoded', (r.hidden || []).map((h) => `${h.method}: ${h.text}`)),
      listPanel('Web addresses', i.url), listPanel('IP addresses', i.ip), listPanel('Tor addresses', i.onion),
      listPanel('Crypto addresses', i.btc.concat(i.eth)), listPanel('Email addresses', i.email),
      listPanel('Registry keys', i.registry), listPanel('File paths', i.path), listPanel('Rust crates', r.detect.crates),
    ].filter(Boolean);
    if (!panels.length) return null;
    return h('div', { class: 'block' }, h('h3', {}, 'Found inside the file'),
      h('p', { class: 'hint' }, 'Text pulled from the file. Finding something here does not mean the program uses it.'), panels);
  }

  function sectionsPanel(p) {
    const rows = p.sections.map((s) => h('tr', {},
      h('td', {}, s.name || '(no name)'), h('td', {}, fmtSize(s.size)),
      h('td', {}, `${s.exec ? 'X' : '-'}${s.write ? 'W' : '-'}`), h('td', {}, s.entropy.toFixed(2)),
      h('td', {}, entropyBar(s.entropy))));
    return h('details', { class: 'panel' },
      h('summary', {}, 'Sections', h('span', { class: 'count' }, String(p.sections.length))),
      h('div', { class: 'inner scroll' },
        h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Size', 'Flags', 'Entropy', 'Random-looking?'].map((t) => h('th', {}, t)))), h('tbody', {}, rows))));
  }

  function entropyBar(e) {
    const fill = h('i');
    fill.style.width = `${(e / 8) * 100}%`; // CSSOM writes are allowed by the page's style-src policy
    return h('div', { class: `bar ${e > 7.2 ? 'hot' : ''}` }, fill);
  }

  function importsPanel(r) {
    const p = r.pe;
    if (!p.imports.length) return null;
    return h('details', { class: 'panel' },
      h('summary', {}, 'Imports', h('span', { class: 'count' }, `${r.importCount} from ${p.imports.length} DLLs`)),
      h('div', { class: 'inner' }, p.imports.map((d) => h('details', { class: 'dll' },
        h('summary', {}, h('b', {}, d.dll), ` (${d.funcs.length}${d.delayed ? ', delay-loaded' : ''})`),
        h('ul', { class: 'list' }, d.funcs.map((fn) => h('li', {}, fn)))))));
  }

  function stringsPanel(r) {
    if (!r.strings.length) return null;
    const list = h('ul', { class: 'list' });
    const note = h('p', { class: 'hint' });
    const render = (q) => {
      const needle = q.trim().toLowerCase();
      const matches = needle ? r.strings.filter((s) => s.toLowerCase().includes(needle)) : r.strings;
      list.replaceChildren(...matches.slice(0, MAX_STRING_ROWS).map((s) => h('li', {}, s)));
      note.textContent = matches.length > MAX_STRING_ROWS ? `Showing the first ${MAX_STRING_ROWS} of ${matches.length.toLocaleString('en-US')} matches.` : `${matches.length.toLocaleString('en-US')} matches.`;
    };
    let timer;
    const search = h('input', { class: 'search', type: 'search', placeholder: 'Search strings...', 'aria-label': 'Search strings', oninput: (e) => {
      clearTimeout(timer);
      const v = e.target.value;
      timer = setTimeout(() => render(v), 120);
    } });
    const panel = h('details', { class: 'panel', ontoggle: (e) => { if (e.target.open && !list.childElementCount) render(''); } },
      h('summary', {}, 'All strings', h('span', { class: 'count' }, r.stringCount.toLocaleString('en-US'))),
      h('div', { class: 'inner' }, search, note, list));
    return panel;
  }

  // Decoded text is hostile input too: it is only ever shown as plain text.
  function decodedBlock(r) {
    if (!r.script) return null;
    return h('div', { class: 'block' }, h('h3', {}, 'Decoded script'),
      h('p', { class: 'hint' }, 'What PEek found after removing the disguises. The script was never run. Do not copy and run this text.'),
      r.script.steps.length ? h('div', { class: 'tags' }, r.script.steps.map((s) => h('span', { class: 'tag' }, s))) : null,
      r.script.layers.map((l, i) => h('details', { class: 'panel code-layer', open: i === r.script.layers.length - 1 },
        h('summary', {}, `Layer ${i + 1}: ${l.label}`),
        h('div', { class: 'inner' }, h('pre', { class: 'code' }, l.text)))));
  }

  function dotnetBlock(r) {
    const d = r.dotnet;
    if (!d) return null;
    const c = d.config;
    return h('div', { class: 'block' }, h('h3', {}, '.NET code'),
      h('p', { class: 'hint' }, `${d.assembly || 'Unnamed program'}, ${d.typeCount.toLocaleString('en-US')} classes and ${d.methodCount.toLocaleString('en-US')} methods. Read from the file, never run.`),
      c ? h('div', { class: 'step config' }, h('b', {}, `Possible settings found in ${c.type}`),
        h('p', {}, 'Values below were read from the code. Do not visit any address shown here.'),
        h('table', {}, h('tbody', {}, c.entries.map((e) => h('tr', {}, h('td', {}, e.name), h('td', {}, e.value)))))) : null,
      listPanel('Native Windows functions', d.pinvokes.map((p) => `${p.dll}: ${p.name}`)),
      listPanel('What its code calls', d.calls),
      listPanel('Classes', d.types),
      listPanel('Libraries it uses', d.references));
  }

  function technicalBlock(r) {
    const panels = [
      r.pe && r.pe.sections.length ? sectionsPanel(r.pe) : null,
      r.pe ? importsPanel(r) : null,
      r.pe && r.pe.exports ? listPanel('Exports', r.pe.exports.names) : null,
      stringsPanel(r),
    ].filter(Boolean);
    if (!panels.length) return null;
    return h('div', { class: 'block' }, h('h3', {}, 'Technical details'), panels);
  }

  function reportBar(r) {
    const json = () => {
      const { strings, ...rest } = r;
      const url = URL.createObjectURL(new Blob([JSON.stringify(rest, null, 2)], { type: 'application/json' }));
      const a = h('a', { href: url, download: `${r.fileName}.peek.json` });
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    };
    return h('div', { class: 'report-bar' },
      h('span', { class: 'file-name' }, r.fileName),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', type: 'button', onclick: async (e) => { const b = e.currentTarget; if (await copyText(PEek.toMarkdown(r))) flash(b, 'Copied'); } }, 'Copy report'),
        h('button', { class: 'btn', type: 'button', onclick: json }, 'Download JSON'),
        r.sha256 ? h('a', { class: 'btn', href: `https://www.virustotal.com/gui/file/${r.sha256}`, target: '_blank', rel: 'noopener noreferrer' }, 'Look up hash') : null,
        batchOpen ? h('button', { class: 'btn', type: 'button', onclick: () => view('batch') }, 'Back to results') : null,
        h('button', { class: 'btn primary', type: 'button', onclick: () => { batchOpen = false; view('home'); } }, 'Scan another file')));
  }

  function tabBar(panes) {
    const tabs = panes.map(([name, pane]) => h('button', { type: 'button', class: 'tab', onclick: () => {
      panes.forEach(([, p]) => { p.hidden = p !== pane; });
      tabs.forEach((t) => t.setAttribute('aria-pressed', String(t.textContent === name)));
    } }, name));
    tabs[0].setAttribute('aria-pressed', 'true');
    tabs[1].setAttribute('aria-pressed', 'false');
    return h('div', { class: 'tabs' }, tabs);
  }

  function show(r) {
    const overview = h('div', {}, [
      r.limits.length ? h('div', { class: 'limits' }, h('ul', {}, r.limits.map((l) => h('li', {}, l)))) : null,
      signaturesBlock(r),
      indicatorsBlock(r),
      assessmentBlock(r),
      aiBlock(r),
    ]);
    const details = h('div', { hidden: true }, [decodedBlock(r), dotnetBlock(r), factsBlock(r), nextStepsBlock(r), foundInsideBlock(r), technicalBlock(r)]);
    $('report').replaceChildren(reportBar(r), generalCard(r), tabBar([['Overview', overview], ['Inside the file', details]]), overview, details);
    view('report');
  }

  function fail(message) {
    $('error-text').textContent = message;
    view('error');
  }

  let batchOpen = false;

  function showBatch(results, skipped) {
    batchOpen = true;
    const rows = results.slice().sort((a, b) => b.report.rating.value - a.report.rating.value).map(({ name, report }) => {
      const r = report.rating;
      return h('tr', { class: 'batch-row', tabindex: '0', onclick: () => show(report), onkeydown: (e) => { if (e.key === 'Enter') show(report); } },
        h('td', {}, h('span', { class: `batch-score ${r.tone}` }, `${r.value}/10`)),
        h('td', { class: 'batch-name' }, name, h('span', { class: 'sub' }, r.label)),
        h('td', {}, h('div', { class: 'tags' }, report.families.map((x) => h('span', { class: 'tag family' }, x.name)), report.markers.slice(0, 4).map((m) => h('span', { class: 'tag' }, m)))));
    });
    const flagged = results.filter((x) => x.report.rating.value >= 5).length;
    $('batch').replaceChildren(...[
      h('div', { class: 'report-bar' },
        h('h2', { class: 'guide-title' }, `${results.length} ${results.length === 1 ? 'file' : 'files'} scanned`),
        h('button', { class: 'btn primary', type: 'button', onclick: () => { batchOpen = false; view('home'); } }, 'Scan more files')),
      h('p', { class: 'lede' }, flagged ? `${flagged} scored 5/10 or higher. Worst results are first. Open a row for the full report.` : 'Nothing scored 5/10 or higher. Open a row for the full report.'),
      results.length ? h('div', { class: 'batch scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Score', 'File', 'Tags'].map((t) => h('th', {}, t)))), h('tbody', {}, rows))) : null,
      skipped.length ? h('div', { class: 'block' }, h('h3', {}, `Not scanned (${skipped.length})`),
        h('ul', { class: 'list' }, skipped.map((x) => h('li', {}, `${x.name}: ${x.why}`)))) : null,
    ].filter(Boolean));
    view('batch');
  }

  async function scan(list) {
    const files = Array.from(list);
    if (!files.length) return;
    batchOpen = false;
    const busy = (text) => { $('busy-name').textContent = text; return new Promise((r) => setTimeout(r, 0)); };
    view('busy');
    await busy(`Taking ${files[0].name} apart...`);
    await new Promise((r) => setTimeout(r, 30)); // let the spinner paint before the heavy work

    const items = [], skipped = [];
    let archive = false;
    for (const file of files) {
      if (!file.size) { skipped.push({ name: file.name, why: 'Empty file' }); continue; }
      try {
        const buffer = await file.arrayBuffer();
        if (/\.zip$/i.test(file.name)) {
          archive = true;
          await busy(`Opening ${file.name}...`);
          const inner = await PEek.zip.extract(buffer);
          for (const x of inner.files) items.push({ name: `${file.name} / ${x.name}`, base: x.name.split('/').pop(), buffer: x.buffer });
          for (const x of inner.skipped) skipped.push({ name: `${file.name} / ${x.name}`, why: x.why });
        } else {
          items.push({ name: file.name, base: file.name, buffer });
        }
      } catch (e) {
        console.error(e);
        skipped.push({ name: file.name, why: e.message || 'Could not be read. It may be too large for this tab.' });
      }
    }

    const results = [];
    for (let i = 0; i < items.length; i++) {
      await busy(`Scanning ${i + 1} of ${items.length}: ${items[i].base}`);
      try {
        results.push({ name: items[i].name, report: await PEek.analyze(items[i].buffer, items[i].base) });
      } catch (e) {
        console.error(e);
        skipped.push({ name: items[i].name, why: 'Could not be analyzed' });
      }
      items[i].buffer = null;
    }
    $('file').value = '';

    if (results.length === 1 && !skipped.length && !archive) show(results[0].report);
    else if (!results.length && skipped.length === 1) fail(`${skipped[0].name}: ${skipped[0].why}`);
    else showBatch(results, skipped);
  }

  // ---- Wiring ----

  $('file').addEventListener('change', (e) => scan(e.target.files));
  $('home-link').addEventListener('click', () => view('home'));
  $('scan-link').addEventListener('click', () => view('home'));
  $('guide-link').addEventListener('click', () => view('guide'));
  $('guide-cta').addEventListener('click', () => view('guide'));
  $('stat-rules').textContent = PEek.rules.RULES.length;
  $('stat-families').textContent = PEek.families.FAMILIES.filter((f) => f.strings || f.hashes || f.sig).length;
  $('stat-tags').textContent = PEek.tags.TAGS.length;
  $('scan-link').setAttribute('aria-current', 'page');
  renderGuide();
  $('error-back').addEventListener('click', () => view('home'));

  let depth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types).includes('Files');
  window.addEventListener('dragenter', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    $('veil').hidden = false;
  });
  window.addEventListener('dragover', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });
  window.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (!depth) $('veil').hidden = true;
  });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    $('veil').hidden = true;
    if (e.dataTransfer.files.length) scan(e.dataTransfer.files);
    else fail('The browser did not hand over a real file. Click the box and choose it instead.');
  });

  window.PEek.ui = { show, scan };
})();
