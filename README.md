
<div align="center">

# PEek

### See what a program really does, before you run it.

**Static analysis. Reverse engineering. AI-powered threat intelligence.**

<br>

[**🌐 Launch PEek**](https://hyperioxhell.github.io/PEek/)

<br>

![Example PEek report](https://github.com/HyperioXHell/PEek/blob/main/report.png?raw=true)

*An example of a PEek analysis report*

<br>

![License](https://img.shields.io/badge/LICENSE-AGPL--3.0-8b5cf6?style=for-the-badge)
![Status](https://img.shields.io/badge/STATUS-EXPERIMENTAL-f59e0b?style=for-the-badge)
![Uploads](https://img.shields.io/badge/UPLOADS-ZERO-22c55e?style=for-the-badge)

</div>

---

## About PEek

PEek is an experimental malware analysis platform designed to help users understand what executable files actually do.

Instead of simply labeling files as safe or malicious, PEek examines their characteristics, identifies suspicious behaviors, and generates detailed AI-assisted analysis reports.

## Features

- **Static Analysis** — Examine executable structures without running the file.
- **Threat Detection** — Identify suspicious behaviors and malware indicators.
- **AI Analysis** — Generate readable explanations of technical findings.
- **Risk Scoring** — Get an overall threat score out of 10.
- **Detailed Reports** — View detected behaviors, classifications, and findings.

## Disclaimer

PEek is experimental. Its results are not a guarantee that a file is safe or malicious. Always treat unknown executables with caution.

---

<div align="center">

**PEek** · Understand before you execute.

</div>

PEEk is a folder analyzer program in your web browser and in GitHub that tells you the features, the risk of running, and the analysis of the folder or file you put in or publish. It was built with the help of Claude OPUS 5.5 AI and with coding and leading from also devs. It has been featured to detect over more than 100+ Malware types, families and also detections. It uses static reverse engineering to do this and it also ensures that the destination file NEVER gets opened on your computer.

PEEk never disassembles your folders. It uses static analysis and takes out code and reads them. So it never runs anything on your PC.

PEEk is a browser-based folder looker that uses Reverse Engineering to scan files of a folder, which then gives the file or program a threat-score out of 10.

## How does PEEk do this?

- Peek uses various different methods, like searching for exact file hashes to detect various malware families.
- It uses heuristic detection to sort real life malware from programs like hacks or injectors. It does this using Windows Function Combinations.
- It also uses searches for suspicious texts and also makes that affect its analysis.
- Looks at file structure and tries to understand what it does, or searches for various types of stuff that might determine if the file has been encrypted or not.
- Script deobfuscation: it strips disguises and decodes hidden layers, then runs all of the above on what's underneath.
- Identity checks: whether the signature matches the file, whether a file claims to be from Google but isn't signed, and fake names like invoice.pdf.exe.

PEEk is strictly static. So PEEk wont do any of the following:

- Running the destined folder in a sandbox.
- Watching programs live on your PC.
- looking at cloud data to determine how trusted a file is.

## FEATURES OF PEEk

### Scanning

- Drag and drop, or click to choose files
- Scan several files at once, with a results table ranked worst first
- Open .zip files in memory, with limits that stop zip bombs (password-protected ZIPs get listed as not scanned)
- Reads Windows programs in depth (.exe, .dll, .sys, .scr)
- Runs script analysis on .ps1, .bat, .cmd, .vbs, .js, .hta and similar files
- Basic text scan for everything else, including Linux, macOS, Android, PDF and Office files

### Detection

- 87 behavior rules covering:
  - stealing and spying
  - sending data out
  - downloading and running code
  - code injection and hiding
  - persistence
  - weakening security
  - damage and ransomware
  - miners
  - spreading through USB or networks
  - reverse shells
  - DDoS
  - IRC bots
  - adware
  - rootkit signs
  - system discovery
- 182 malware families, matched by file hash, byte signature or text markers, each labeled exact, byte signature, strong or possible
- 241 byte signatures that match compiled code, even when a file's readable text is hidden
- 30 tags:
  - 23 types, such as TROJAN, RAT, WORM, RANSOMWARE, STEALER, CRYPTINJECT, TROJANCRYPTINJECT, CHEAT_INJECTOR, GAME_CHEAT and RISKWARE
  - 7 behaviors, such as DISCOVERY, PERSISTENCE and DEFENSE_EVASION
- MITRE ATT&CK IDs on findings where one fits, linked to MITRE's site

### .NET reverse engineering

- Reads classes, methods, native calls and libraries from .NET programs
- Walks each method's IL code to see what it calls
- Extracts hardcoded settings such as a server, port and mutex

### Hidden text hunting

- Finds dangerous text hidden with XOR, repeating-key XOR, shifted bytes, ROT13, reversed text and hex text

### Script deobfuscation

- Removes batch carets and variable tricks
- Removes PowerShell backticks and character codes
- Rejoins split strings, and undoes Chr(), fromCharCode, hex escapes, reversed text and find-and-replace tricks
- Decodes Base64 and gzip, including nested layers
- Shows each decoded layer in the report, and never runs the script

### Program analysis

- Built with: .NET, Go, Rust, Python (PyInstaller, Nuitka, py2exe), Electron, Tauri, Delphi, AutoIt, VB6, Node.js, Java wrappers, C/C++, plus Unity, Unreal, Godot and Qt
- Packers and protectors: UPX, Themida, VMProtect, ConfuserEx and more, plus unknown packer detection
- Installers: NSIS, Inno Setup, InstallShield, WiX and others
- Digital signatures: shows the signer and checks that the signature still matches the file
- File details: claimed company and product, version, compile date, admin requests and developer debug paths
- Raw data: sections with entropy, imports, exports, Rust crates and searchable strings
- Found inside: URLs, IPs, registry keys, file paths, emails, crypto addresses and Tor addresses

### Reports

- Threat score out of 10 with a 10-segment meter and classification
- Box under the score showing family and type
- Plain-English verdict and explanation for every finding, with the evidence behind it
- Behavioral indicators table
- Overview and Inside the file tabs
- Next steps for reverse engineers, with commands to copy
- SHA-256 hash and a VirusTotal lookup button that sends only the hash
- Copy the report as Markdown, or download it as JSON
- Clear warnings when PEek can't see inside a file

### AI opinion (optional)

- Copy for AI: copies a ready-made prompt with the report's findings to paste into any AI
- Analyze with local AI: uses Ollama on your own PC, so nothing leaves your computer. Each user needs to install Ollama and download a model
- Only runs when you click, and only uses report data, never the file itself
- AI can be wrong and can never change the score

### Malware guide

- How PEek makes its decisions, with an example
- Every malware type and behavior explained, including when each tag is added
- 183 families listed, with search and type filters

### Privacy and safety

- Runs entirely in your browser, and the browser blocks the page from reaching anywhere except Ollama on your own PC
- Never runs the files you scan
- File contents are treated as hostile and only shown as plain text
- Parser and ZIP reader tested against hundreds of randomly corrupted files

### Design and setup

- Works by double-clicking index.html, or hosted free on GitHub Pages
- Needs no install, dependencies or build step
- Works on desktop and phone, with light and dark mode
- Works offline.

## Credits

Created by HyperioXHell.

Many family text markers and all byte signatures come from Elastic's public protections-artifacts YARA rules (https://github.com/elastic/protections-artifacts), Copyright Elasticsearch B.V., licensed under the Elastic License 2.0. A copy of that license is in third-party/ELASTIC-LICENSE.txt.

## License

PEek is Copyright (C) 2026 HyperioXHell and is licensed under the GNU AGPL-3.0, with one added term: modified versions must keep the "Created by HyperioXHell" credit. See LICENSE and NOTICE.

The files js/signatures-data.js and js/families-more.js are not under the AGPL. They stay under the Elastic License 2.0.

## Why PEEk?

Peek is completely free (as of right now). It was made for experimentation and for help. It was made to also see also how a program can detect viruses using Static Reverse Engineering and without running.

## Quick Warning

This project is still experimental. And i never guarantee 100 percent correctness, and no antivirus or folder analyzer can. It is basically not possible.

As of right now, it has not been tested with real malware, but it has gone through strict tests with imitation programs. Like every antivirus and file analyzer, it can't be 100 percent correct, so you should still expect false positives and missed detections. This program only looks at behavior, code and structure using RE and looking at its integrity.
