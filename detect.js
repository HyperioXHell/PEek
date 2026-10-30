/*
 * PEek — detect.js
 * Figures out what a program was built with (language, framework, installer, packer, protector)
 * and what a reverse engineer should reach for next.
 *
 * Each signature gets the feature bag `f` built in analyze.js:
 *   f.pe (parsed PE or null), f.dlls (Set, lowercase), f.hay (all strings), f.low (lowercased),
 *   f.sections (Set of section names)
 */
(function (root) {
  'use strict';

  const has = (f, ...needles) => needles.some((n) => f.hay.includes(n));
  const hasLow = (f, ...needles) => needles.some((n) => f.low.includes(n));
  const dll = (f, ...names) => names.some((n) => f.dlls.has(n));
  const sect = (f, ...names) => names.some((n) => f.sections.has(n));
  // Real installers carry their payload after the last section; other files may only mention the names.
  const payload = (f) => f.pe && !f.pe.isDll && f.pe.overlay.size > 4096;

  const GHIDRA = { title: 'Disassemble it', how: 'Load it into Ghidra (free) or IDA Free to read the code, and x64dbg to step through it while it runs (in a VM).' };

  // Order matters: the first language match wins the headline.
  const SIGNATURES = [
    // ---- Packers & protectors ----
    { id: 'upx', kind: 'packer', name: 'UPX packer', test: (f) => sect(f, 'UPX0', 'UPX1', 'UPX2') || has(f, 'UPX!'),
      next: { title: 'Unpack UPX first', how: 'UPX is reversible. Unpack it, then analyze the result:', cmd: 'upx -d FILE -o unpacked.exe' } },
    { id: 'mpress', kind: 'packer', name: 'MPRESS packer', test: (f) => sect(f, '.MPRESS1', '.MPRESS2') },
    { id: 'aspack', kind: 'packer', name: 'ASPack packer', test: (f) => sect(f, '.aspack', '.adata') },
    { id: 'pecompact', kind: 'packer', name: 'PECompact packer', test: (f) => sect(f, 'PEC2', 'pec1', 'pec2', 'PEC2TO', 'PEC2MO') },
    { id: 'petite', kind: 'packer', name: 'Petite packer', test: (f) => sect(f, '.petite') },
    { id: 'themida', kind: 'protector', name: 'Themida / WinLicense', test: (f) => sect(f, '.themida', '.winlice') || (sect(f, '.boot') && hasLow(f, 'themida', 'winlicense')),
      next: { title: 'Heavy protection', how: 'Themida encrypts and virtualizes code, so static analysis will not get far. Use x64dbg with the ScyllaHide plugin in a VM and dump the process once it has unpacked itself.' } },
    { id: 'vmprotect', kind: 'protector', name: 'VMProtect', test: (f) => sect(f, '.vmp0', '.vmp1', '.vmp2'),
      next: { title: 'Heavy protection', how: 'VMProtect turns code into a custom virtual machine. Expect slow going: dynamic analysis (x64dbg + ScyllaHide) is usually the practical route.' } },
    { id: 'enigma', kind: 'protector', name: 'Enigma Protector', test: (f) => sect(f, '.enigma1', '.enigma2') },
    { id: 'confuser', kind: 'protector', name: 'ConfuserEx (.NET obfuscator)', test: (f) => f.pe && f.pe.isDotNet && has(f, 'ConfuserEx', 'Confuser.Core', 'ConfusedByAttribute'),
      next: { title: 'Deobfuscate first', how: 'Run de4dot (or a ConfuserEx-specific unpacker) before opening it in dnSpyEx:', cmd: 'de4dot FILE' } },
    { id: 'dotnetreactor', kind: 'protector', name: '.NET Reactor', test: (f) => f.pe && f.pe.isDotNet && has(f, '.NET Reactor', 'Eziriz') },
    { id: 'eazfuscator', kind: 'protector', name: 'Eazfuscator.NET', test: (f) => f.pe && f.pe.isDotNet && has(f, 'Eazfuscator') },
    { id: 'smartassembly', kind: 'protector', name: 'SmartAssembly', test: (f) => f.pe && f.pe.isDotNet && has(f, 'SmartAssembly.Attributes', 'PoweredByAttribute') },
    { id: 'costura', kind: 'framework', name: 'Costura (DLLs bundled inside)', test: (f) => f.pe && f.pe.isDotNet && hasLow(f, 'costura.') },

    // ---- Installers & self-extractors ----
    { id: 'nsis', kind: 'installer', name: 'NSIS installer', test: (f) => payload(f) && has(f, 'Nullsoft', 'NSIS Error', 'nsis.sf.net'),
      next: { title: 'Look inside the installer', how: '7-Zip can open NSIS installers and show the files they would install:', cmd: '7z x FILE -oextracted' } },
    { id: 'inno', kind: 'installer', name: 'Inno Setup installer', test: (f) => payload(f) && has(f, 'Inno Setup', 'JR.Inno.Setup'),
      next: { title: 'Look inside the installer', how: 'innoextract unpacks Inno Setup installers without running them:', cmd: 'innoextract -e FILE' } },
    { id: 'installshield', kind: 'installer', name: 'InstallShield installer', test: (f) => payload(f) && has(f, 'InstallShield') },
    { id: 'wixburn', kind: 'installer', name: 'WiX Burn bundle', test: (f) => sect(f, '.wixburn'),
      next: { title: 'Look inside the bundle', how: 'Extract the embedded MSI packages with the WiX toolset:', cmd: 'wix burn extract FILE -o extracted' } },
    { id: 'squirrel', kind: 'installer', name: 'Squirrel installer', test: (f) => has(f, 'SquirrelSetup', 'Squirrel.Windows', 'Squirrel-Install'),
      next: { title: 'Look inside the installer', how: 'Open it with 7-Zip; the app is inside a .nupkg (a renamed .zip).' } },
    { id: 'sfx7z', kind: 'installer', name: '7-Zip self-extractor', test: (f) => payload(f) && has(f, '7zSFX', '7-Zip SFX', ';!@Install@!UTF-8!') },
    { id: 'rarsfx', kind: 'installer', name: 'WinRAR self-extractor', test: (f) => payload(f) && has(f, 'WinRAR SFX', 'RarSFX', 'WinRAR self-extracting') },

    // ---- Languages & runtimes ----
    { id: 'pyinstaller', kind: 'language', name: 'Python (PyInstaller)', test: (f) => has(f, '_MEIPASS', 'PyInstaller', 'pyi-runtime-tmpdir', 'pyi-windows-manifest-filename'),
      next: { title: 'Get the Python source back', how: 'Extract the bundled .pyc files, then decompile them with pycdc or pylingual.io:', cmd: 'python pyinstxtractor.py FILE' } },
    { id: 'nuitka', kind: 'language', name: 'Python (Nuitka)', test: (f) => hasLow(f, 'nuitka'),
      next: { title: 'Compiled Python', how: 'Nuitka compiles Python to C, so there is no decompiler. Onefile builds unpack to %TEMP%\\onefile_* when run. Grab them in a VM, then use Ghidra. Strings still reveal module names.' } },
    { id: 'py2exe', kind: 'language', name: 'Python (py2exe)', test: (f) => hasLow(f, 'py2exe') },
    { id: 'autoit', kind: 'language', name: 'AutoIt script', test: (f) => has(f, 'AU3!EA06', '>>>AUTOIT SCRIPT<<<', 'AutoIt v3'),
      next: { title: 'Get the script back', how: 'AutoIt scripts are stored inside the .exe and can be recovered:', cmd: 'pip install autoit-ripper && autoit-ripper FILE out' } },
    { id: 'pkg', kind: 'language', name: 'Node.js (pkg)', test: (f) => has(f, 'pkg/prelude/bootstrap.js', 'PKG_EXECPATH'),
      next: { title: 'Get the JavaScript back', how: 'The JS source or V8 bytecode is bundled in the .exe. Try pkg-unpacker to pull it out.' } },
    { id: 'nexe', kind: 'language', name: 'Node.js (nexe)', test: (f) => has(f, '<nexe~~sentinel>') },
    { id: 'bun', kind: 'language', name: 'JavaScript (Bun compiled)', test: (f) => has(f, '---- Bun! ----') },
    { id: 'deno', kind: 'language', name: 'JavaScript (Deno compiled)', test: (f) => has(f, 'd3n0l4nd') },
    { id: 'electron', kind: 'language', name: 'Electron (JavaScript)', test: (f) => has(f, 'electron.asar', 'ELECTRON_RUN_AS_NODE'),
      next: { title: 'Read the JavaScript', how: 'The app code is in resources\\app.asar next to the .exe. Extract it and you have the source:', cmd: 'npx @electron/asar extract resources/app.asar app-src' } },
    { id: 'tauri', kind: 'language', name: 'Tauri (Rust + web UI)', test: (f) => has(f, '__TAURI', 'tauri://localhost', '__TAURI_INTERNALS__'),
      next: { title: 'Two halves', how: 'The web UI (HTML/JS) is embedded in the .exe, brotli-compressed. The backend is Rust: use Ghidra. Strings list the Rust crates it uses.' } },
    { id: 'dotnet', kind: 'language', name: '.NET (C# / VB.NET)', test: (f) => f.pe && f.pe.isDotNet,
      next: { title: 'Decompile to C#', how: '.NET decompiles to readable C# almost perfectly. Open it in dnSpyEx or ILSpy.' } },
    { id: 'go', kind: 'language', name: 'Go', test: (f) => has(f, 'Go build ID:', 'runtime.gopanic', 'go.buildid', 'runtime.goexit'),
      next: { title: 'Recover Go function names', how: 'Go binaries keep their function names. GoReSym recovers them, then load the result into Ghidra or IDA:', cmd: 'GoReSym -t -d -p FILE > symbols.json' } },
    { id: 'rust', kind: 'language', name: 'Rust', test: (f) => has(f, '/rustc/', '\\rustc\\', 'library\\std\\src', 'library/std/src', 'rust_panic', 'RUST_BACKTRACE'),
      next: { title: 'Rust tips', how: 'Use Ghidra or IDA. Panic messages and .cargo paths in strings show the crate names and source files.' } },
    { id: 'nim', kind: 'language', name: 'Nim', test: (f) => has(f, 'fatal.nim', '@m..@s', 'nimGC', 'NimMain') },
    { id: 'vb6', kind: 'language', name: 'Visual Basic 6', test: (f) => dll(f, 'msvbvm60.dll', 'msvbvm50.dll'),
      next: { title: 'VB6 decompiling', how: 'VB Decompiler (lite version is free) recovers forms and P-Code.' } },
    { id: 'java', kind: 'language', name: 'Java (wrapped in .exe)', test: (f) => hasLow(f, 'launch4j', 'exe4j', 'jsmooth', 'jpackage'),
      next: { title: 'Get the .jar out', how: 'The .jar is embedded. Open the .exe with 7-Zip to pull it out, then read it in JADX or Recaf.' } },
    { id: 'delphi', kind: 'language', name: 'Delphi / C++Builder', test: (f) => has(f, 'Borland\\Delphi', 'SOFTWARE\\Borland\\Delphi', 'Embarcadero Delphi', 'Software\\Embarcadero') || (sect(f, 'CODE', 'DATA', 'BSS') && has(f, 'TObject')),
      next: { title: 'Delphi tools', how: 'IDR (Interactive Delphi Reconstructor) recovers forms and class names. Then use Ghidra with the Dhrake scripts.' } },
    { id: 'mingw', kind: 'language', name: 'C/C++ (GCC / MinGW)', test: (f) => has(f, 'GCC: (', 'Mingw-w64 runtime failure', 'mingw_') },
    { id: 'msvc', kind: 'language', name: 'C/C++ (Microsoft Visual C++)', test: (f) => f.pe && f.pe.hasRich && !f.pe.isDotNet },

    // ---- Frameworks & engines (shown alongside the language) ----
    { id: 'unity', kind: 'framework', name: 'Unity game engine', test: (f) => dll(f, 'unityplayer.dll') || has(f, 'UnityPlayer.dll'),
      next: { title: 'Unity game', how: 'If GameAssembly.dll sits next to it, it is IL2CPP: run Il2CppDumper on it with global-metadata.dat. Otherwise open <Game>_Data\\Managed\\Assembly-CSharp.dll in dnSpyEx.' } },
    { id: 'unreal', kind: 'framework', name: 'Unreal Engine', test: (f) => has(f, 'FEngineLoop', 'UnrealEngine', 'UE4Game', 'UnrealGame'),
      next: { title: 'Unreal game', how: 'Use Dumper-7 or UE4SS to dump the SDK (class names and offsets), and FModel to browse .pak assets.' } },
    { id: 'godot', kind: 'framework', name: 'Godot engine', test: (f) => has(f, 'Godot Engine', 'godotengine.org'),
      next: { title: 'Godot game', how: 'GDRE Tools can recover the project and GDScript from the .pck.' } },
    { id: 'qt', kind: 'framework', name: 'Qt framework', test: (f) => dll(f, 'qt5core.dll', 'qt6core.dll', 'qt5cored.dll', 'qt6cored.dll') },
  ];

  // Collects Rust crate names from paths like ".cargo\registry\src\index.crates.io-xxxx\reqwest-0.11.4\..."
  function rustCrates(hay) {
    const re = /registry[\\/]src[\\/][^\\/\s]+[\\/]([a-z0-9_-]+?)-(\d+\.\d+\.\d+)/gi;
    const out = new Set();
    let m;
    while ((m = re.exec(hay)) && out.size < 80) out.add(m[1]);
    return Array.from(out).sort();
  }

  function detect(f) {
    const found = SIGNATURES.filter((s) => { try { return s.test(f); } catch (e) { return false; } });
    const language = found.find((s) => s.kind === 'language') || null;
    const next = found.filter((s) => s.next).map((s) => s.next);

    // A high-entropy code section with almost no imports usually means an unknown packer.
    const p = f.pe;
    let unknownPacker = false;
    if (p && !found.some((s) => s.kind === 'packer' || s.kind === 'protector' || s.kind === 'installer')) {
      const hot = p.sections.filter((s) => s.exec && s.rawSize > 4096 && s.entropy > 7.2);
      const importCount = p.imports.reduce((n, d) => n + d.funcs.length, 0);
      if (hot.length && (importCount < 30 || !p.isDotNet && hot.some((s) => s.write))) unknownPacker = true;
    }
    if (unknownPacker) {
      next.unshift({ title: 'Probably packed', how: 'The code looks encrypted or compressed and there is no known packer signature. Run it in a VM under x64dbg, let it unpack itself, then dump it with Scylla.' });
    }
    if (p && !p.isDotNet && !found.some((s) => s.next && s.kind !== 'framework' && s.kind !== 'packer')) next.push(GHIDRA);

    return {
      language: language ? language.name : (p ? 'Native code (unknown compiler)' : null),
      tags: found.map((s) => ({ id: s.id, kind: s.kind, name: s.name })),
      unknownPacker,
      crates: found.some((s) => s.id === 'rust' || s.id === 'tauri') ? rustCrates(f.hay) : [],
      next,
    };
  }

  root.PEek = root.PEek || {};
  root.PEek.detect = detect;
})(typeof window !== 'undefined' ? window : globalThis);
