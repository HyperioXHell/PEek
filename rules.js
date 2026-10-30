/*
 * PEek — rules.js
 * Behavior rules. Each rule looks for a combination of Windows API calls and text inside the file
 * and explains, in plain English, what that combination lets the program do.
 *
 * A rule's test(f) returns evidence (a non-empty array) when it fires, or null.
 * f.apis is a Map of normalized API name (lowercase, A/W suffix dropped) -> name as written in the file.
 * f.low is every extracted string, lowercased and joined with newlines.
 *
 * Severity: high = classic malware behavior, medium = risky but has legit uses,
 * low = worth knowing, info = context only (never affects the score).
 */
(function (root) {
  'use strict';

  const api = (f, ...names) => names.filter((n) => f.apis.has(n)).map((n) => ({ t: 'api', v: f.apis.get(n) }));
  const txt = (f, ...needles) => needles.filter((n) => f.low.includes(n)).map((n) => ({ t: 'text', v: n }));
  const re = (f, regex) => { const m = f.low.match(regex); return m ? [{ t: 'text', v: m[0].trim() }] : []; };
  const meta = (v) => ({ t: 'meta', v });
  const all = (...groups) => (groups.every((g) => g.length) ? groups.flat() : null);
  const atLeast = (n, list) => (list.length >= n ? list : null);
  const distinct = (list) => new Set(list.map((e) => e.v)).size;

  const BROWSERS = {
    Chrome: ['\\google\\chrome\\', 'google/chrome/'], Edge: ['\\microsoft\\edge\\'], Brave: ['brave-browser'],
    Opera: ['opera software', 'opera gx'], Firefox: ['mozilla\\firefox', 'logins.json', 'key4.db', 'cookies.sqlite'],
    Yandex: ['yandexbrowser', 'yandex\\yandexbrowser'], Vivaldi: ['\\vivaldi\\'], Chromium: ['\\chromium\\user data'],
  };
  const BROWSER_FILES = ['login data', 'web data', 'local state', 'encrypted_key', 'logins.json', 'key4.db', 'cookies.sqlite', '\\network\\cookies'];
  const WALLETS = ['wallet.dat', '\\exodus\\', 'exodus.wallet', '\\electrum\\', 'atomic\\local storage', 'atomic wallet', 'coinomi', 'jaxx', 'guarda',
    'armory', 'ethereum\\keystore', 'ledger live', 'wasabi wallet', 'bitcoin\\wallets', 'nkbihfbeogaeaoehlefnkodbefgpgknn' /* MetaMask */,
    'bfnaelmomeimhlpmgjnjophhpkkoljpa' /* Phantom */, 'ibnejdfjmmkpcnlpebklmnkoeoihofec' /* TronLink */, 'fhbohimaelbohpjbbldcngcnapndodjp' /* Binance */];
  const SUSPICIOUS_PROJECT = /(stealer|grabber|keylog|inject(or|ion)|crypter|payload|malware|loader|ransom|rootkit|botnet|\brat\b|backdoor|dropper|spread|clipper|token.?log|hvnc)/i;
  const BRANDS = ['google', 'adobe', 'mozilla', 'apple', 'nvidia', 'valve', 'discord', 'zoom', 'oracle', 'intel', 'amd', 'logitech', 'spotify', 'epic games', 'riot games', 'steam'];
  const SYSTEM_NAMES = ['svchost.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'dwm.exe', 'taskhostw.exe',
    'rundll32.exe', 'conhost.exe', 'spoolsv.exe', 'wininit.exe', 'runtimebroker.exe', 'sihost.exe', 'ctfmon.exe'];

  const RULES = [
    // ---------------- Stealing data ----------------
    { id: 'browser-stealer', sev: 'high', cat: 'Stealing data', title: 'Goes after saved browser passwords and cookies',
      why: 'It knows where several browsers keep saved passwords, cookies and the key that protects them. This is the core of an "info stealer". Browsers that import from other browsers do it too, but almost nothing else does.',
      test: (f) => {
        const hits = Object.entries(BROWSERS).filter(([, keys]) => keys.some((k) => f.low.includes(k))).map(([b]) => meta(b));
        const files = txt(f, ...BROWSER_FILES);
        if (hits.length >= 3 && files.length >= 2) return hits.concat(files);
        if (hits.length >= 2 && files.length >= 3 && api(f, 'cryptunprotectdata').length) return hits.concat(files, api(f, 'cryptunprotectdata'));
        return null;
      } },
    { id: 'wallet-stealer', sev: 'high', cat: 'Stealing data', title: 'Looks for cryptocurrency wallets',
      why: 'It references the files or browser extensions of several crypto wallets. Stealers grab these to empty your wallet.',
      test: (f) => atLeast(2, txt(f, ...WALLETS)) },
    { id: 'discord-stealer', sev: 'high', cat: 'Stealing data', title: 'Tries to steal Discord logins',
      why: 'It looks inside Discord\'s local storage, or contains the token pattern used by Discord "token grabbers". With your token, someone can log in as you without your password.',
      test: (f) => {
        const hits = txt(f, 'discord\\local storage\\leveldb', 'discordcanary\\local storage', 'discordptb\\local storage', 'dqw4w9wgxcq');
        const pattern = re(f, /\[\\w-\]\{24(,26)?\}\\\.\[\\w-\]\{6\}\\\.\[\\w-\]\{(25,110|27,38|27)\}|mfa\\\.\[\\w-\]\{84\}/);
        return hits.length || pattern.length ? hits.concat(pattern) : null;
      } },
    { id: 'telegram-stealer', sev: 'high', cat: 'Stealing data', title: 'Tries to copy your Telegram session',
      why: 'It looks for Telegram Desktop\'s "tdata" folder. Copying it lets someone open your Telegram account on their own computer.',
      test: (f) => all(txt(f, '\\tdata', 'tdata\\'), txt(f, 'telegram desktop', 'telegram.exe')) },
    { id: 'app-credentials', sev: 'medium', cat: 'Stealing data', title: 'Collects saved logins from other apps',
      why: 'It knows where other programs (Steam, FileZilla, Minecraft, Roblox, VPNs, Wi-Fi) keep logins or session cookies. Stealers sweep these up in bulk.',
      test: (f) => {
        const hits = txt(f, '.roblosecurity', 'loginusers.vdf', 'ssfn', 'recentservers.xml', 'sitemanager.xml', 'launcher_accounts.json',
          'netsh wlan show profile', 'key=clear', 'nordvpn\\', 'openvpn connect\\profiles', 'protonvpn', '\\.minecraft\\', 'growtopia', 'save.dat');
        if (txt(f, '.roblosecurity').length && hits.length >= 2) return hits;
        return atLeast(3, hits);
      } },
    { id: 'clipper', sev: 'high', cat: 'Stealing data', title: 'Can swap crypto addresses you copy',
      why: 'It reads and rewrites the clipboard and contains crypto wallet addresses or wallet-address patterns. "Clipper" malware replaces the address you paste with the attacker\'s.',
      test: (f) => {
        const clip = api(f, 'getclipboarddata', 'setclipboarddata', 'gettext', 'settext').concat(txt(f, 'clipboard'));
        const addr = f.iocs.btc.slice(0, 3).concat(f.iocs.eth.slice(0, 3)).map((v) => ({ t: 'text', v }))
          .concat(re(f, /\(bc1\|\[13\]\)|\^0x\[a-fa-f0-9\]\{40\}|\[13\]\[a-km-za-hj-np-z1-9\]\{25,3[45]\}/));
        const writes = api(f, 'setclipboarddata').length || (f.low.includes('clipboard') && api(f, 'settext').length);
        return writes ? all(clip, addr) : null;
      } },

    // ---------------- Spying ----------------
    { id: 'keylogger', sev: 'high', cat: 'Spying', title: 'Can record what you type',
      why: 'It watches the keyboard globally, turns key codes into characters, and notes which window you are typing into. That combination is the recipe for a keylogger.',
      test: (f) => all(api(f, 'setwindowshookex', 'getasynckeystate', 'getrawinputdata'), api(f, 'getforegroundwindow'),
        api(f, 'getwindowtext'), api(f, 'tounicode', 'toascii', 'tounicodeex', 'toasciiex', 'mapvirtualkey', 'mapvirtualkeyex', 'getkeynametext')) },
    { id: 'webcam', sev: 'medium', cat: 'Spying', title: 'Can use the webcam',
      why: 'It uses the old Windows video capture API that remote-access trojans use to grab webcam frames. Modern video apps rarely use it.',
      test: (f) => atLeast(1, api(f, 'capcreatecapturewindow', 'capgetdriverdescription')) },
    { id: 'screenshot', sev: 'info', cat: 'Spying', title: 'Can take screenshots',
      why: 'It can copy what is on the screen into an image. Common in normal apps (drawing, screen sharing), and also used by spyware.',
      test: (f) => all(api(f, 'bitblt', 'stretchblt'), api(f, 'getdesktopwindow', 'getwindowdc', 'createdc'), api(f, 'getdibits', 'createcompatiblebitmap')) },
    { id: 'microphone', sev: 'info', cat: 'Spying', title: 'Can record audio',
      why: 'It can open the microphone. Expected for voice chat or recording apps.',
      test: (f) => all(api(f, 'waveinopen'), api(f, 'waveinstart')) },

    // ---------------- Sending data out ----------------
    { id: 'discord-webhook', sev: 'high', cat: 'Sending data out', title: 'Sends data to a Discord webhook',
      why: 'A Discord webhook URL is baked into the file. Real software almost never ships with one; stealers and "loggers" use webhooks to send what they grabbed straight to the attacker\'s Discord.',
      test: (f) => atLeast(1, f.iocs.url.filter((u) => /discord(app)?\.com\/api\/webhooks\//i.test(u)).slice(0, 3).map((v) => ({ t: 'text', v }))
        .concat(txt(f, 'discord.com/api/webhooks', 'discordapp.com/api/webhooks')).slice(0, 3)) },
    { id: 'telegram-bot', sev: 'medium', cat: 'Sending data out', title: 'Talks to a Telegram bot',
      why: 'It contains a Telegram bot address or token. Some legit tools send notifications this way, but stealers often use it to ship stolen data.',
      test: (f) => atLeast(1, txt(f, 'api.telegram.org/bot').concat(f.iocs.telegramToken.slice(0, 2).map((v) => ({ t: 'text', v })))) },
    { id: 'throwaway-hosts', sev: 'medium', cat: 'Sending data out', title: 'Uses throwaway file, paste or tunnel services',
      why: 'It mentions services where anyone can host a file, paste text or open a tunnel without an account. Malware uses them to fetch payloads and hide where it reports to.',
      test: (f) => atLeast(1, txt(f, 'pastebin.com/raw', 'paste.ee/', 'hastebin.com', 'rentry.co', 'transfer.sh', 'anonfiles', 'gofile.io', 'file.io/',
        'ngrok.io', 'ngrok-free.app', 'duckdns.org', 'ddns.net', 'no-ip.org', 'portmap.io', 'playit.gg', 'trycloudflare.com', 'serveo.net',
        'temp.sh', 'catbox.moe', 'webhook.site', 'requestbin', 'pipedream.net', 'bashupload.com')) },
    { id: 'ip-lookup', sev: 'low', cat: 'Sending data out', title: 'Looks up your public IP or location',
      why: 'It asks an online service for your IP address or location. Stealers add this to the report they send home; some normal apps use it too.',
      test: (f) => atLeast(1, txt(f, 'ip-api.com', 'ipinfo.io', 'api.ipify.org', 'icanhazip.com', 'checkip.amazonaws.com', 'ipwho.is', 'geolocation-db.com', 'myexternalip.com', 'ipapi.co', 'freegeoip')) },
    { id: 'tor', sev: 'medium', cat: 'Sending data out', title: 'Uses the Tor network',
      why: 'It contains .onion addresses or Tor components. Tor hides who is on the other end of a connection; ransomware uses it for payment pages and control servers.',
      test: (f) => atLeast(1, f.iocs.onion.slice(0, 3).map((v) => ({ t: 'text', v })).concat(re(f, /(?:^|[\\/"'\s])tor\.exe\b/m), txt(f, 'torrc', 'socks5h://'))) },
    { id: 'network', sev: 'info', cat: 'Sending data out', title: 'Connects to the internet',
      why: 'It can open network connections. Expected for most modern apps.',
      test: (f) => atLeast(1, api(f, 'internetopen', 'winhttpopen', 'urldownloadtofile', 'wsastartup', 'connect', 'getaddrinfo', 'httpsendrequest')
        .concat(txt(f, 'system.net.http', 'system.net.webclient', 'system.net.sockets')).slice(0, 4)) },

    // ---------------- Downloading & running other things ----------------
    { id: 'downloader', sev: 'medium', cat: 'Downloads & runs things', title: 'Downloads files and runs them',
      why: 'It can download a file from the internet and start it. That is how "loaders" install the real malware after you run something innocent-looking. Installers and updaters do this legitimately.',
      test: (f) => {
        const dl = api(f, 'urldownloadtofile').concat(txt(f, 'downloadfile(', '.downloadstring(', 'invoke-webrequest', 'start-bitstransfer', 'bitsadmin /transfer', 'certutil -urlcache', 'downloaddata('));
        const run = api(f, 'shellexecute', 'shellexecuteex', 'winexec', 'createprocess').concat(txt(f, 'process.start', 'start-process'));
        return all(dl, run);
      } },
    { id: 'powershell', sev: 'high', cat: 'Downloads & runs things', title: 'Runs hidden or encoded PowerShell',
      why: 'It launches PowerShell with tricks that hide what the command does (encoded, hidden window, download-and-execute). Attackers love this because it leaves no file behind.',
      test: (f) => {
        if (!f.low.includes('powershell')) return null;
        const tricks = txt(f, '-encodedcommand', ' -enc ', '-windowstyle hidden', '-w hidden', 'invoke-expression', 'frombase64string', 'downloadstring', '-executionpolicy bypass', '-ep bypass', '-noprofile -noninteractive')
          .concat(re(f, /\biex\s*[(\s]/));
        return distinct(tricks) >= 3 ? tricks : null;
      } },
    { id: 'lolbins', sev: 'medium', cat: 'Downloads & runs things', title: 'Abuses built-in Windows tools',
      why: 'It uses Windows\' own tools (mshta, regsvr32, certutil, rundll32, wmic) in ways attackers do, so the malicious part looks like normal Windows activity.',
      test: (f) => atLeast(1, txt(f, 'mshta http', 'mshta.exe http', 'mshta vbscript', 'scrobj.dll', 'certutil -decode', 'certutil.exe -decode', 'rundll32 javascript', 'rundll32.exe javascript',
        'wmic process call create', 'regsvr32 /s /n /u /i:', 'msiexec /q /i http', 'cmstp.exe /au')) },
    { id: 'script-dropper', sev: 'medium', cat: 'Downloads & runs things', title: 'Script that fetches or launches programs',
      why: 'It uses scripting objects that can download files, write them to disk and run them. Common in malicious .vbs, .js and .hta files.',
      test: (f) => all(txt(f, 'adodb.stream', 'msxml2.xmlhttp', 'msxml2.serverxmlhttp', 'winhttp.winhttprequest'), txt(f, 'wscript.shell', 'shell.application')) },

    // ---------------- Hiding inside other programs ----------------
    { id: 'injection', sev: 'high', cat: 'Hiding', title: 'Can inject code into other programs',
      why: 'It has every piece needed to write code into another running program and start it there. Malware does this to hide inside trusted processes. Debuggers, game overlays and some security tools do it too.',
      test: (f) => all(api(f, 'virtualallocex', 'ntallocatevirtualmemory', 'zwallocatevirtualmemory', 'ntmapviewofsection', 'zwmapviewofsection'),
        api(f, 'writeprocessmemory', 'ntwritevirtualmemory', 'zwwritevirtualmemory', 'ntmapviewofsection'),
        api(f, 'createremotethread', 'createremotethreadex', 'ntcreatethreadex', 'rtlcreateuserthread', 'queueuserapc', 'ntqueueapcthread', 'setthreadcontext')) },
    { id: 'hollowing', sev: 'high', cat: 'Hiding', title: 'Can disguise itself as another program',
      why: 'It can start a legit program paused, swap out its code and resume it ("process hollowing"). Task Manager then shows a harmless name while the malware runs inside.',
      test: (f) => all(api(f, 'createprocess', 'createprocessinternal'), api(f, 'ntunmapviewofsection', 'zwunmapviewofsection'),
        api(f, 'setthreadcontext', 'wow64setthreadcontext'), api(f, 'resumethread')) },
    { id: 'memory-access', sev: 'medium', cat: 'Hiding', title: 'Reads or changes other programs\' memory',
      why: 'It opens other running programs and reads or writes their memory. Game cheats, trainers, debuggers and memory scanners do this; so does malware that steals data from inside other apps.',
      test: (f) => (f.fired.has('injection') ? null : all(api(f, 'openprocess', 'ntopenprocess'), api(f, 'readprocessmemory', 'writeprocessmemory', 'ntreadvirtualmemory', 'ntwritevirtualmemory'))) },
    { id: 'anti-analysis', sev: 'medium', cat: 'Hiding', title: 'Checks if it is being watched',
      why: 'It looks for virtual machines, sandboxes or analysis tools, usually to behave nicely when a researcher runs it. Anti-cheat systems do this too.',
      test: (f) => {
        const hits = txt(f, 'vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'vmware tools', 'virtualbox guest', 'sbiedll.dll', 'sandboxie', 'cuckoo', 'wine_get_unix_file_name',
          'wireshark', 'procmon', 'processhacker', 'process hacker', 'x64dbg', 'x32dbg', 'ollydbg', 'ida64', 'idaq', 'fiddler', 'httpdebugger', 'dnspy', 'cheatengine', 'pestudio', 'qemu-ga', 'vmsrvc', 'joeboxserver', 'any.run');
        return distinct(hits) >= 3 ? hits : null;
      } },
    { id: 'anti-debug', sev: 'low', cat: 'Hiding', title: 'Tries to detect debuggers',
      why: 'It uses several tricks to notice a debugger. Copy-protection and anti-cheat do this; so does malware that wants to resist analysis.',
      test: (f) => atLeast(2, api(f, 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'zwqueryinformationprocess', 'ntsetinformationthread', 'zwsetinformationthread', 'debugactiveprocess', 'blockinput')
        .concat(txt(f, 'ntglobalflag', 'processdebugport', 'threadhidefromdebugger'))) },
    { id: 'dynamic-apis', sev: 'low', cat: 'Hiding', title: 'Hides which Windows features it uses',
      why: 'It imports almost nothing and looks up functions at runtime instead, so its capabilities are not visible from the outside. Typical for packed programs and shellcode loaders.',
      test: (f) => (f.pe && !f.pe.isDotNet && f.importCount > 0 && f.importCount < 12 && api(f, 'getprocaddress').length ? [meta(`Only ${f.importCount} imports`), ...api(f, 'getprocaddress', 'loadlibrary', 'ldrgetprocedureaddress')] : null) },

    // ---------------- Staying on the computer ----------------
    { id: 'autorun', sev: 'medium', cat: 'Starts with Windows', title: 'Adds itself to Windows startup',
      why: 'It writes to the registry keys or folders that launch programs at login. Plenty of normal apps do this, but malware does it to survive reboots.',
      test: (f) => all(txt(f, '\\currentversion\\run', 'start menu\\programs\\startup', 'shell:startup'), api(f,'regsetvalueex', 'regsetkeyvalue', 'copyfile', 'movefile', 'createfile').concat(txt(f, 'setvalue', 'reg add', 'reg.exe add', 'new-itemproperty', 'set-itemproperty'))) },
    { id: 'scheduled-task', sev: 'medium', cat: 'Starts with Windows', title: 'Creates scheduled tasks',
      why: 'It creates a scheduled task, which can relaunch it at login or every few minutes, even with admin rights. Updaters do this; so does persistent malware.',
      test: (f) => atLeast(1, re(f, /schtasks(\.exe)?\s*\/create/).concat(txt(f, 'register-scheduledtask', 'new-scheduledtask'))) },
    { id: 'startup-hijack', sev: 'high', cat: 'Starts with Windows', title: 'Hijacks a Windows startup mechanism',
      why: 'It touches deep Windows settings (Winlogon shell, AppInit_DLLs, SilentProcessExit) that run code whenever Windows or another program starts. Normal software almost never needs these.',
      test: (f) => atLeast(1, txt(f, 'winlogon\\shell', 'winlogon\\userinit', 'appinit_dlls', 'silentprocessexit')) },
    { id: 'service', sev: 'low', cat: 'Starts with Windows', title: 'Installs a Windows service',
      why: 'It can install a background service that starts with Windows and runs with high privileges. Normal for drivers, VPNs and updaters.',
      test: (f) => atLeast(1, api(f, 'createservice').concat(re(f, /\bsc(\.exe)?\s+create\b/))) },

    // ---------------- Weakening security ----------------
    { id: 'defender-off', sev: 'high', cat: 'Weakens security', title: 'Tries to turn off or blind Windows Defender',
      why: 'It changes Defender settings, disables real-time protection or adds exclusions so its files are not scanned. Legit software has no reason to do this.',
      test: (f) => atLeast(1, txt(f, 'disablerealtimemonitoring', 'disableantispyware', 'add-mppreference', 'set-mppreference', 'windows defender\\exclusions',
        'disablebehaviormonitoring', 'disableioavprotection', 'mpcmdrun.exe -removedefinitions', 'tamperprotection')) },
    { id: 'uac-bypass', sev: 'high', cat: 'Weakens security', title: 'Tries to get admin rights without asking',
      why: 'It uses known tricks (fodhelper, eventvwr, sdclt, CMSTP) to get administrator rights without showing you the UAC prompt.',
      test: (f) => atLeast(1, txt(f, 'ms-settings\\shell\\open\\command', 'mscfile\\shell\\open\\command', 'folder\\shell\\open\\command', 'exefile\\shell\\open\\command')
        .concat(all(txt(f, 'fodhelper', 'computerdefaults', 'sdclt', 'eventvwr'), txt(f, 'delegateexecute')) || [])) },
    { id: 'firewall', sev: 'medium', cat: 'Weakens security', title: 'Changes firewall settings',
      why: 'It runs commands that open ports or switch off the Windows firewall. Game servers and installers sometimes add rules; switching it off is a red flag.',
      test: (f) => atLeast(1, txt(f, 'advfirewall set allprofiles state off', 'netsh firewall set opmode disable', 'netsh advfirewall firewall add rule', 'netsh firewall add allowedprogram')) },
    { id: 'block-tools', sev: 'high', cat: 'Weakens security', title: 'Blocks Task Manager or other tools',
      why: 'It sets policies that disable Task Manager, Registry Editor or the command prompt, which stops you from finding and removing it.',
      // cmd.exe itself reads DisableCMD, so that policy only counts alongside another one.
      test: (f) => (txt(f, 'disabletaskmgr', 'disableregistrytools').length ? txt(f, 'disabletaskmgr', 'disableregistrytools', 'disablecmd') : null) },
    { id: 'kill-av', sev: 'high', cat: 'Weakens security', title: 'Looks for antivirus programs to stop them',
      why: 'It carries a list of antivirus process names and can terminate processes. Malware does this to kill protection before acting.',
      test: (f) => {
        const av = txt(f, 'msmpeng.exe', 'avp.exe', 'avgui.exe', 'mbam.exe', 'mbamservice', 'bdagent.exe', 'ekrn.exe', 'avastui.exe', 'mcshield.exe', 'nortonsecurity', 'savservice', 'sophos', 'cylancesvc', 'csfalconservice');
        return distinct(av) >= 3 && api(f, 'terminateprocess', 'ntterminateprocess').length ? av.concat(api(f, 'terminateprocess', 'ntterminateprocess')) : null;
      } },
    { id: 'debug-privilege', sev: 'medium', cat: 'Weakens security', title: 'Gives itself access to every process',
      why: 'It enables SeDebugPrivilege, which lets it open and tamper with any process on the system, including protected ones.',
      test: (f) => all(api(f, 'adjusttokenprivileges', 'rtladjustprivilege'), txt(f, 'sedebugprivilege')) },
    { id: 'motw', sev: 'low', cat: 'Weakens security', title: 'Removes the "downloaded from the internet" mark',
      why: 'It touches the Zone.Identifier stream that Windows uses to warn you about downloaded files. Removing it skips those warnings.',
      test: (f) => atLeast(1, txt(f, ':zone.identifier', 'unblock-file')) },
    { id: 'hosts-file', sev: 'medium', cat: 'Weakens security', title: 'Edits the hosts file',
      why: 'It touches Windows\' hosts file, which can redirect websites or block antivirus updates. Some ad-blockers and dev tools also edit it.',
      test: (f) => atLeast(1, txt(f, 'drivers\\etc\\hosts')) },

    // ---------------- Damage ----------------
    { id: 'delete-backups', sev: 'high', cat: 'Damage', title: 'Deletes backups and recovery points',
      why: 'It deletes Windows shadow copies or disables recovery so you cannot restore your files. This is a hallmark of ransomware.',
      test: (f) => atLeast(1, txt(f, 'delete shadows', 'shadowcopy delete', 'shadowcopy where', 'delete catalog -quiet', 'recoveryenabled no', 'bootstatuspolicy ignoreallfailures', 'delete systemstatebackup', 'resize shadowstorage')) },
    { id: 'ransom-note', sev: 'high', cat: 'Damage', title: 'Contains a ransom note',
      why: 'It contains text telling a victim that their files were encrypted and how to pay. That is ransomware.',
      test: (f) => atLeast(2, txt(f, 'your files have been encrypted', 'your files are encrypted', 'all of your files', 'all your files have been', 'to decrypt your files',
        'decrypt your files', 'pay the ransom', 'recover your files', 'your personal id', 'download tor browser', 'private key will be destroyed')) },
    { id: 'encrypts-files', sev: 'low', cat: 'Damage', title: 'Walks through folders and encrypts data',
      why: 'It can list files across folders and encrypt data. Backup tools and archivers do this; combined with other signs it points to ransomware.',
      test: (f) => all(api(f, 'findfirstfile', 'findfirstfileex').concat(txt(f, 'directory.getfiles', 'enumeratefiles')),
        api(f, 'cryptencrypt', 'bcryptencrypt').concat(txt(f, 'createencryptor', 'rijndaelmanaged', 'aescryptoserviceprovider'))) },
    { id: 'raw-disk', sev: 'medium', cat: 'Damage', title: 'Can write directly to the disk',
      why: 'It opens the physical disk directly, bypassing files. Disk utilities need this; wipers and bootkits use it to destroy or replace the boot code.',
      test: (f) => all(txt(f, '\\\\.\\physicaldrive', '\\\\.\\c:'), api(f, 'writefile', 'deviceiocontrol')) },
    { id: 'bsod', sev: 'high', cat: 'Damage', title: 'Can crash Windows on purpose',
      why: 'It can trigger a blue screen or mark itself as a critical process so that closing it crashes the PC. Used by malware to stop you from killing it.',
      test: (f) => atLeast(1, api(f, 'ntraiseharderror', 'rtlsetprocessiscritical', 'zwraiseharderror').concat(txt(f, 'breakonterminatio'))) },
    { id: 'boot-overwrite', sev: 'high', cat: 'Damage', title: 'Can overwrite the boot record',
      why: 'It can write straight to the first physical disk and can also crash Windows on purpose. Together, that is how destructive malware replaces the boot code so the PC can no longer start.',
      test: (f) => (f.fired.has('bsod') ? all(txt(f, '\\\\.\\physicaldrive0'), api(f, 'writefile')) : null) },
    { id: 'miner', sev: 'high', cat: 'Damage', title: 'Contains a cryptocurrency miner',
      why: 'It has mining pool addresses or miner settings. Hidden miners use your CPU/GPU to make money for someone else, slowing your PC and raising your power bill.',
      test: (f) => atLeast(1, txt(f, 'stratum+tcp://', 'stratum+ssl://', 'stratum2+tcp://', 'xmrig', '--donate-level', '--cpu-max-threads-hint', 'moneroocean', 'minexmr', 'nanopool.org', 'supportxmr', 'nicehash.com', 'ethermine.org')) },

    // ---------------- Identity & disguise ----------------
    { id: 'signature-broken', sev: 'high', cat: 'Identity', title: 'Its digital signature does not match the file',
      why: 'The file carries a signature, but the file was changed after signing, or the signature was copied from another program to look trustworthy.',
      test: (f) => (f.signatureValid === false ? [meta(`Signature claims: ${f.pe.signature.signer || 'unknown signer'}`)] : null) },
    { id: 'fake-extension', sev: 'high', cat: 'Identity', title: 'Uses a fake file extension',
      why: 'The file name pretends to be a document or picture but is really a program (e.g. "invoice.pdf.exe"), or uses a hidden character to flip the name around.',
      test: (f) => (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|mov|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|hta|lnk)$/i.test(f.fileName) || /[\u202e\u202d]/.test(f.fileName) ? [meta(f.fileName)] : null) },
    { id: 'brand-impersonation', sev: 'medium', cat: 'Identity', title: 'Claims to be from a well-known company but is not signed',
      why: 'Its details say it is made by a big company, but it has no digital signature. Real software from these companies is always signed.',
      test: (f) => {
        const v = f.pe && f.pe.versionInfo;
        if (!v || f.pe.signature.present) return null;
        const claims = `${v.CompanyName || ''} ${v.LegalCopyright || ''}`.toLowerCase();
        const brand = BRANDS.find((b) => new RegExp(`\\b${b}\\b`).test(claims));
        return brand ? [meta(`Company: ${v.CompanyName || v.LegalCopyright}`), meta('No digital signature')] : null;
      } },
    { id: 'microsoft-unsigned', sev: 'low', cat: 'Identity', title: 'Says it is from Microsoft but has no embedded signature',
      why: 'Windows\' own files are often signed through a separate catalog, so this is normal for files that came with Windows. For a file you downloaded, it is suspicious.',
      test: (f) => {
        const v = f.pe && f.pe.versionInfo;
        return v && !f.pe.signature.present && /microsoft/i.test(`${v.CompanyName || ''} ${v.LegalCopyright || ''}`) ? [meta(`Company: ${v.CompanyName}`)] : null;
      } },
    { id: 'system-name', sev: 'medium', cat: 'Identity', title: 'Uses the name of a Windows system process',
      why: 'It is named like a core Windows process, but its details do not say Microsoft. Malware picks these names so it blends in in Task Manager.',
      test: (f) => {
        const v = (f.pe && f.pe.versionInfo) || {};
        const name = f.fileName.toLowerCase();
        const orig = (v.OriginalFilename || '').toLowerCase();
        const hit = SYSTEM_NAMES.find((n) => n === name || n === orig);
        return hit && !/microsoft/i.test(v.CompanyName || '') ? [meta(`Named ${hit}`)] : null;
      } },
    { id: 'suspicious-project', sev: 'medium', cat: 'Identity', title: 'The developer\'s project name is suspicious',
      why: 'The developer left a build path inside the file, and the project name contains words like "stealer", "rat" or "injector".',
      test: (f) => {
        const pdb = f.pe && f.pe.debug.pdb;
        return pdb && SUSPICIOUS_PROJECT.test(pdb) ? [meta(pdb)] : null;
      } },
    { id: 'injector-tool', sev: 'medium', cat: 'Identity', title: 'Looks like a DLL injector',
      why: 'It mentions injecting DLLs and has the abilities to do it. These tools load code into other programs and are mostly used for game cheats. They can get accounts banned, and many downloads of them hide malware.',
      test: (f) => all(txt(f, 'manual map', 'manualmap', 'dll injector', 'dllinjector', 'inject dll', 'injectdll', 'loadlibrary injection', 'extreme injector'),
        api(f, 'writeprocessmemory', 'ntwritevirtualmemory', 'zwwritevirtualmemory')) },
    { id: 'game-cheat', sev: 'low', cat: 'Identity', title: 'Looks like a game cheat or trainer',
      why: 'It mentions game memory offsets or cheat features. Not malware by itself, but it can get your account banned, and fake cheats are one of the most common ways malware spreads.',
      test: (f) => {
        const hits = txt(f, 'dwentitylist', 'dwlocalplayer', 'dwviewmatrix', 'm_ihealth', 'm_iteamnum', 'aimbot', 'triggerbot', 'wallhack', 'no recoil', 'norecoil', 'bunnyhop', 'esp box', 'glow esp', 'm_hplayerpawn', 'dwlocalplayerpawn');
        return distinct(hits) >= 2 ? hits : null;
      } },

    // ---------------- Spreading & remote control ----------------
    { id: 'usb-spread', sev: 'high', cat: 'Spreading', title: 'Can spread through USB drives',
      why: 'It looks for removable drives, can copy files, and mentions autorun.inf, the file old USB worms used to start themselves on other PCs.',
      test: (f) => all(txt(f, 'autorun.inf'), api(f, 'getdrivetype', 'getlogicaldrives', 'getlogicaldrivestrings').concat(txt(f, 'drivetype')), api(f, 'copyfile', 'copyfileex').concat(txt(f, 'copy-item'))) },
    { id: 'network-spread', sev: 'medium', cat: 'Spreading', title: 'Can reach other computers on the network',
      why: 'It lists network shares and mentions admin shares such as ADMIN$ and C$. Worms use these to copy themselves to other PCs. Backup and IT tools use them too.',
      test: (f) => all(txt(f, '\\admin$', '\\c$', '\\ipc$'), api(f, 'netshareenum', 'netserverenum', 'wnetaddconnection2', 'wnetenumresource', 'wnetopenenum')) },
    { id: 'reverse-shell', sev: 'medium', cat: 'Remote control', title: 'May give someone a remote command line',
      why: 'It combines a raw network socket with starting a command shell. That is the usual recipe for a reverse shell, which lets someone type commands on your PC from far away.',
      // WSASocket alone is not enough: Rust's standard library imports it in every network program.
      test: (f) => all(api(f, 'wsasocket'), api(f, 'wsaconnect'), api(f, 'createprocess'), txt(f, 'cmd.exe', 'powershell.exe')) },
    { id: 'ddos', sev: 'high', cat: 'Network attacks', title: 'Has website flooding tools',
      why: 'It names several flooding attacks. Malware like this uses your PC and internet connection to help knock websites offline.',
      test: (f) => atLeast(2, txt(f, 'udpflood', 'udp flood', 'synflood', 'syn flood', 'httpflood', 'http flood', 'tcpflood', 'tcp flood', 'slowloris')) },
    { id: 'irc-bot', sev: 'medium', cat: 'Remote control', title: 'Takes orders through IRC chat',
      why: 'It contains IRC chat commands. Old botnets used IRC channels to give orders to thousands of infected PCs. Real chat clients contain these too.',
      test: (f) => atLeast(2, txt(f, 'privmsg', 'nickserv', 'join #')) },
    { id: 'force-extension', sev: 'medium', cat: 'Unwanted software', title: 'Can force browser extensions on you',
      why: 'It mentions the browser policy used to install extensions you cannot remove. Adware and browser hijackers use it to inject ads and track what you do. Companies also use it to manage their own PCs.',
      test: (f) => atLeast(1, txt(f, 'extensioninstallforcelist')) },
    { id: 'kernel-tamper', sev: 'medium', cat: 'Hiding', title: 'Touches deep Windows kernel structures',
      why: 'This driver references internal kernel tables that rootkits change to hide files and processes. Anti-cheat and security drivers can also touch them.',
      test: (f) => (f.dlls.has('ntoskrnl.exe') ? atLeast(1, txt(f, 'keservicedescriptortable', 'psloadedmodulelist')) : null) },
    { id: 'discovery', sev: 'low', cat: 'Discovery', title: 'Collects information about your system',
      why: 'It contains several commands or queries for learning about the PC: the user, network, running programs or antivirus. Attackers do this to decide what to do next. Support tools do too.',
      test: (f) => {
        const hits = txt(f, 'systeminfo', 'whoami', 'ipconfig /all', 'tasklist', 'net user', 'net view', 'arp -a', 'nltest', 'route print', 'netstat -', 'select * from antivirusproduct', 'win32_computersystem');
        return distinct(hits) >= 3 ? hits : null;
      } },
    { id: 'script-obfuscated', sev: 'medium', cat: 'Hiding', title: 'This script is deliberately disguised',
      why: 'PEek had to peel off several layers of disguise to read it. Normal scripts have no reason to split up words or hide text like this. Minified web code can look similar, so check what the decoded version does.',
      test: (f) => (f.script && f.script.steps.length >= 2 ? f.script.steps.map(meta) : null) },
    { id: 'amsi-bypass', sev: 'high', cat: 'Hiding', title: 'Tries to switch off Windows script scanning',
      why: 'It targets AMSI, the feature that lets antivirus see scripts as they run. Scripts disable it so that whatever they do next goes unseen. Legitimate scripts have no reason to touch it.',
      test: (f) => (f.kind === 'script' ? atLeast(1, txt(f, 'amsiutils', 'amsiinitfailed', 'amsiscanbuffer', 'amsicontext')) : null) },
    { id: 'fileless', sev: 'high', cat: 'Hiding', title: 'Downloads code and runs it straight from memory',
      why: 'It fetches code from the internet and runs it right away without saving a file. This "download and execute" trick leaves little for antivirus to find.',
      test: (f) => (f.kind === 'script' ? all(re(f, /\biex\b|invoke-expression/), txt(f, 'downloadstring', 'downloaddata', 'invoke-webrequest', 'invoke-restmethod', 'iwr ', 'irm ')) : null) },
    { id: 'memory-loader', sev: 'high', cat: 'Hiding', title: 'Loads a program directly into memory',
      why: 'It loads compiled code into memory without a file on disk, or sets up memory to run raw code. Malware uses this to avoid being scanned.',
      test: (f) => (f.kind === 'script' ? atLeast(1, txt(f, '[reflection.assembly]::load', '[system.reflection.assembly]::load', 'getdelegateforfunctionpointer', 'invoke-shellcode', 'invoke-reflectivepeinjection')) : null) },
    { id: 'script-embedded-exe', sev: 'high', cat: 'Hiding', title: 'Has a Windows program hidden inside the script',
      why: 'A complete Windows program is encoded inside this script. Scripts carry programs this way to drop or run them. It was not analyzed separately, so extract it and scan it on its own.',
      test: (f) => (f.script && f.script.embeddedExe ? [meta('Encoded Windows program found')] : null) },
    // ---------------- .NET code ----------------
    { id: 'dotnet-config', sev: 'high', cat: 'Remote control', title: 'Has a hardcoded server to connect to',
      why: 'PEek read the program\'s code and found a settings class holding a server address, plus a port or similar settings. Remote access trojans usually store their control server exactly like this. Normal client apps can do it too, so check whether you recognize the address.',
      test: (f) => {
        const c = f.dotnet && f.dotnet.config;
        return c ? [meta(`Class ${c.type}`), ...c.hosts.slice(0, 3).map((v) => ({ t: 'text', v })), ...c.ports.slice(0, 2).map((v) => meta(`Port ${v}`))] : null;
      } },
    { id: 'dotnet-remote-control', sev: 'medium', cat: 'Remote control', title: 'Its code has what a remote control tool needs',
      why: 'PEek read the program\'s code and found it opens network connections, starts programs, and also captures the screen or reads the registry. Together those are the core of a RAT. Remote support tools use the same pieces.',
      test: (f) => {
        if (!f.netCalls) return null;
        const has = (...names) => names.filter((n) => f.netCalls.has(n));
        const net = has('system.net.sockets.tcpclient..ctor', 'system.net.sockets.socket..ctor', 'system.net.sockets.tcpclient.connect', 'system.net.sockets.socket.connect');
        const run = has('system.diagnostics.process.start');
        const extra = has('system.drawing.graphics.copyfromscreen', 'microsoft.win32.registrykey.setvalue', 'microsoft.win32.registrykey.createsubkey', 'microsoft.win32.registry.setvalue');
        return net.length && run.length && extra.length ? [...net, ...run, ...extra].slice(0, 6).map((v) => ({ t: 'api', v })) : null;
      } },
    { id: 'dotnet-memory-load', sev: 'medium', cat: 'Hiding', title: 'Loads code from memory while running',
      why: 'Its code loads another program straight from memory. Loaders use this to run a hidden payload that never touches the disk. Apps that bundle their own libraries do this too.',
      test: (f) => (f.netCalls && f.netCalls.has('system.reflection.assembly.load') && f.netCalls.has('system.convert.frombase64string') ? [{ t: 'api', v: 'Assembly.Load' }, { t: 'api', v: 'Convert.FromBase64String' }] : null) },
    { id: 'dotnet-obfuscated', sev: 'low', cat: 'Hiding', title: 'Its code names have been scrambled',
      why: 'Most class names in this .NET program are garbled or meaningless, which is what obfuscators do to stop people reading the code. Paid software does this too.',
      test: (f) => (f.dotnet && f.dotnet.obfuscatedNames > 0.6 ? [meta(`${Math.round(f.dotnet.obfuscatedNames * 100)}% of class names look scrambled`)] : null) },

    { id: 'hidden-strings', sev: 'medium', cat: 'Hiding', title: 'Hides dangerous text with encoding tricks',
      why: 'PEek found commands, addresses or Windows function names that were deliberately scrambled, using tricks like XOR or reversing the text. Programs have little reason to hide these. The decoded text was also checked by the other rules.',
      test: (f) => atLeast(1, (f.hidden || []).slice(0, 5).map((h) => ({ t: 'text', v: `${h.method}: ${h.text.slice(0, 60)}` }))) },
    { id: 'risky-extension', sev: 'medium', cat: 'Identity', title: 'A program hiding behind a risky file type',
      why: 'This is a real Windows program, but it uses a file type like .scr, .pif or .com. Windows runs these like normal programs, and people often do not realize that, which is why malware likes them.',
      test: (f) => (f.pe && !f.pe.isDll && /\.(scr|pif|com|cpl)$/i.test(f.fileName) ? [meta(f.fileName)] : null) },
    { id: 'no-extension', sev: 'low', cat: 'Identity', title: 'A program with no file extension',
      why: 'This is a real Windows program, but its name has no extension, so it does not look like one. Attackers do this to make a file look harmless or to get past simple filters.',
      test: (f) => (f.pe && !/\.[a-z0-9]{1,8}$/i.test(f.fileName) ? [meta(f.fileName)] : null) },
    { id: 'encoded-strings', sev: 'medium', cat: 'Hiding', title: 'Hides commands or addresses with Base64',
      why: 'Readable text was found after decoding Base64, and it contains things like commands, web addresses or file paths. Hiding text this way is a common trick for slipping past simple scanners.',
      test: (f) => atLeast(1, (f.decoded || []).filter((s) => /https?:|cmd|powershell|\.exe|delete|webhook|\\/i.test(s)).slice(0, 5).map((v) => ({ t: 'text', v }))) },
    { id: 'embedded-exe', sev: 'low', cat: 'Hiding', title: 'Has another program hidden inside',
      why: 'It contains a second Windows program inside itself. Droppers unpack their payload this way. Installers and bundled apps also carry programs inside them.',
      test: (f) => {
        if (f.detect.tags.some((t) => t.kind === 'installer')) return null;
        const marker = 'this program cannot be run in dos mode';
        const first = f.low.indexOf(marker);
        return first >= 0 && f.low.indexOf(marker, first + 1) >= 0 ? [meta('More than one program header found')] : null;
      } },
    { id: 'encrypted-blob', sev: 'info', cat: 'Hiding', title: 'Carries a large encrypted-looking block of data',
      why: 'Part of the file looks random, which is how encrypted payloads look. Compressed images and game data can look the same, so this only matters alongside other signs.',
      test: (f) => {
        if (!f.pe || f.detect.tags.some((t) => t.kind === 'installer')) return null;
        return atLeast(1, f.pe.sections.filter((s) => !s.exec && s.rawSize > 32768 && s.entropy > 7.4).map((s) => meta(`${s.name || '(no name)'}: entropy ${s.entropy.toFixed(2)} / 8`)));
      } },

    // ---------------- Deep file checks ----------------
    { id: 'overlay-payload', sev: 'low', cat: 'Structure', title: 'Has encrypted-looking data hidden after the program',
      why: 'A large block of random-looking data sits after the end of the program, where Windows never loads it. Installers keep their files there, but it is also a place to hide a payload.',
      test: (f) => {
        const p = f.pe;
        if (!p || p.signature.present || f.detect.tags.some((t) => t.kind === 'installer')) return null;
        return p.overlay.size > 65536 && p.overlay.entropy > 7.5 ? [meta(`${Math.round(p.overlay.size / 1024)} KB, entropy ${p.overlay.entropy.toFixed(2)} / 8`)] : null;
      } },
    { id: 'odd-sections', sev: 'low', cat: 'Structure', title: 'Has unusual section names',
      why: 'Compilers use normal names for the parts of a program. Blank or garbled names usually mean a packer or a tool changed the file by hand.',
      test: (f) => (f.pe ? atLeast(1, f.pe.sections.filter((s) => !/^[\x21-\x7e]+$/.test(s.name)).map((s) => meta(s.name ? `Garbled section name` : 'Section with no name'))) : null) },
    { id: 'fake-timestamp', sev: 'low', cat: 'Structure', title: 'Its build date is in the future',
      why: 'The date stored in the file has not happened yet. Some tools fake this date to confuse analysts.',
      test: (f) => (f.pe && !f.pe.debug.repro && f.pe.timestamp * 1000 > Date.now() + 86400000 ? [meta(new Date(f.pe.timestamp * 1000).toISOString().slice(0, 10))] : null) },
    { id: 'tls-early-code', sev: 'low', cat: 'Structure', title: 'Runs code before the program officially starts',
      why: 'It uses a TLS callback, which runs before the normal starting point, and it imports very little. Malware uses this to run before a debugger can stop it.',
      test: (f) => (f.pe && !f.pe.isDotNet && f.pe.hasTls && f.importCount > 0 && f.importCount < 12 ? [meta(`TLS callback with only ${f.importCount} imports`)] : null) },

    // ---------------- Structure ----------------
    { id: 'packed', sev: 'medium', cat: 'Structure', title: 'Code is packed or encrypted',
      why: 'Most of the code is compressed or encrypted and only unpacks itself when run, so it cannot be checked without running it. Some legit programs do this; a lot of malware does.',
      test: (f) => (f.detect.unknownPacker ? f.pe.sections.filter((s) => s.exec && s.entropy > 7.2).map((s) => meta(`${s.name || '(no name)'}: entropy ${s.entropy.toFixed(2)} / 8`)) : null) },
    { id: 'protector', sev: 'low', cat: 'Structure', title: 'Protected against reverse engineering',
      why: 'It uses a commercial protector or packer. Games and paid software use these against cracking, but malware uses the same tools to dodge antivirus.',
      test: (f) => atLeast(1, f.detect.tags.filter((t) => t.kind === 'protector' || t.kind === 'packer').map((t) => meta(t.name))) },
    { id: 'wx-section', sev: 'low', cat: 'Structure', title: 'Has memory that is both writable and executable',
      why: 'A section of the program can be changed and run at the same time. Self-modifying code and unpackers need that; normal compilers avoid it.',
      test: (f) => (f.pe && !f.detect.unknownPacker ? atLeast(1, f.pe.sections.filter((s) => s.exec && s.write).map((s) => meta(s.name || '(no name)'))) : null) },
    { id: 'odd-entry', sev: 'medium', cat: 'Structure', title: 'Starts running from an unusual place',
      why: 'The program\'s starting point is not inside a normal code section. Packers and file infectors do this.',
      test: (f) => {
        const p = f.pe;
        if (!p || p.isDotNet || !p.entryRva || p.isDll) return null;
        if (!p.entrySection) return [meta('Entry point is outside every section')];
        return p.entrySection.exec ? null : [meta(`Entry point is in non-executable section ${p.entrySection.name}`)];
      } },
    { id: 'driver', sev: 'low', cat: 'Structure', title: 'This is a kernel driver',
      why: 'Drivers run inside the Windows kernel with full control of the PC. Normal for hardware and anti-cheat; dangerous if it comes from somewhere you do not trust.',
      test: (f) => (f.pe && (f.pe.subsystem === 1 || f.dlls.has('ntoskrnl.exe')) ? [meta('Native subsystem / imports ntoskrnl.exe')] : null) },
    { id: 'requires-admin', sev: 'info', cat: 'Structure', title: 'Asks for administrator rights',
      why: 'It asks Windows for admin rights when it starts, so you will see a UAC prompt. Normal for installers and system tools.',
      test: (f) => (f.pe && f.pe.manifest && /requireAdministrator|highestAvailable/i.test(f.pe.manifest.level || '') ? [meta(`requestedExecutionLevel = ${f.pe.manifest.level}`)] : null) },
    { id: 'hardcoded-ips', sev: 'low', cat: 'Sending data out', title: 'Contains hard-coded IP addresses',
      why: 'It has raw internet addresses inside it instead of website names. Malware often connects straight to its control server this way.',
      test: (f) => atLeast(1, f.iocs.ip.filter((ip) => !/^(8\.8\.[48]\.[48]|1\.[01]\.[01]\.1|9\.9\.9\.9|208\.67\.22[02]\.22[02])/.test(ip)).slice(0, 5).map((v) => ({ t: 'text', v }))) },
  ];

  // MITRE ATT&CK technique for each rule, where one fits.
  const ATTACK = {
    'browser-stealer': 'T1555.003', 'wallet-stealer': 'T1005', 'discord-stealer': 'T1528', 'telegram-stealer': 'T1005', 'app-credentials': 'T1555', clipper: 'T1115',
    keylogger: 'T1056.001', webcam: 'T1125', screenshot: 'T1113', microphone: 'T1123',
    'discord-webhook': 'T1567.004', 'telegram-bot': 'T1567', 'throwaway-hosts': 'T1102', 'ip-lookup': 'T1016', tor: 'T1090.003', 'hardcoded-ips': 'T1071',
    downloader: 'T1105', powershell: 'T1059.001', lolbins: 'T1218', 'script-dropper': 'T1059.005',
    injection: 'T1055', hollowing: 'T1055.012', 'anti-analysis': 'T1497', 'anti-debug': 'T1622', 'dynamic-apis': 'T1027.007',
    autorun: 'T1547.001', 'scheduled-task': 'T1053.005', 'startup-hijack': 'T1547.004', service: 'T1543.003',
    'defender-off': 'T1562.001', 'uac-bypass': 'T1548.002', firewall: 'T1562.004', 'block-tools': 'T1562', 'kill-av': 'T1562.001', 'debug-privilege': 'T1134', motw: 'T1553.005', 'hosts-file': 'T1565.001',
    'delete-backups': 'T1490', 'ransom-note': 'T1486', 'encrypts-files': 'T1486', 'raw-disk': 'T1561', 'boot-overwrite': 'T1561.002', bsod: 'T1529', miner: 'T1496',
    'signature-broken': 'T1036.001', 'fake-extension': 'T1036.007', 'system-name': 'T1036.005',
    'usb-spread': 'T1091', 'network-spread': 'T1021.002', 'reverse-shell': 'T1059.003', ddos: 'T1498', 'irc-bot': 'T1071', 'force-extension': 'T1176', 'kernel-tamper': 'T1014',
    'overlay-payload': 'T1027.009', 'odd-sections': 'T1027', 'fake-timestamp': 'T1070.006', 'tls-early-code': 'T1622',
    'dotnet-config': 'T1071', 'dotnet-remote-control': 'T1219', 'dotnet-memory-load': 'T1620', 'dotnet-obfuscated': 'T1027',
    'injector-tool': 'T1055.001', 'hidden-strings': 'T1027', 'risky-extension': 'T1036.008', 'no-extension': 'T1036',
    'script-obfuscated': 'T1027', 'amsi-bypass': 'T1562.001', fileless: 'T1059.001', 'memory-loader': 'T1620', 'script-embedded-exe': 'T1027.009',
    discovery: 'T1082', 'encoded-strings': 'T1027', 'embedded-exe': 'T1027.009', packed: 'T1027.002', driver: 'T1547.006',
  };

  // Rules run in order; a few later rules look at f.fired to avoid double-counting.
  function run(f) {
    f.fired = new Set();
    const findings = [];
    for (const rule of RULES) {
      let evidence = null;
      try { evidence = rule.test(f); } catch (e) { evidence = null; }
      if (evidence && evidence.length) {
        f.fired.add(rule.id);
        findings.push({ id: rule.id, sev: rule.sev, cat: rule.cat, title: rule.title, why: rule.why, attack: ATTACK[rule.id] || null, evidence: dedupe(evidence).slice(0, 12) });
      }
    }
    return findings;
  }

  function dedupe(evidence) {
    const seen = new Set();
    return evidence.filter((e) => (seen.has(e.t + e.v) ? false : seen.add(e.t + e.v)));
  }

  root.PEek = root.PEek || {};
  root.PEek.rules = { run, RULES };
})(typeof window !== 'undefined' ? window : globalThis);
