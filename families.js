/*
 * PEek — families.js
 * Known malware families, used for detection and for the Malware guide page.
 *
 * A family is only named when its own markers are found:
 *   hashes  exact SHA-256 of a known sample ("exact")
 *   strings lowercase text, at least `need` must be present, reported as `conf`
 * "strong" = text specific to the family. "possible" = weaker text, which may also appear in
 * research code, source code or security tools. Never add a marker ordinary software could contain.
 * An entry with neither is listed in the guide but cannot be detected yet.
 *
 * Sources: `verified: true` markers come from Elastic's public YARA rules (elastic/protections-artifacts).
 * NanoCore also matches Joe Sandbox rule hits. SalatStealer: CYFIRMA report via securitricks.com.
 * VShell, SNOWLIGHT: sysdig.com/blog/unc5174-chinese-threat-actor-vshell.
 * KawaiiUnicorn: ANY.RUN report addresses. NeptuneRAT: Joe Sandbox configs. Stormser: a Triage report.
 * AsyncRAT, Lumma and MEMZ use well-known public markers not checked against a rule set or samples.
 */
(function (root) {
  'use strict';

  const TYPES = {
    'Remote access trojan': 'Gives a stranger control of your PC: your files, your screen and often your webcam and keyboard.',
    'Info stealer': 'Grabs saved passwords, browser cookies, crypto wallets and app logins, then sends them to the attacker, usually within seconds.',
    Ransomware: 'Locks your files with encryption and demands payment to get them back.',
    Backdoor: 'Keeps a hidden way into a machine so attackers can come back whenever they want.',
    Loader: 'A small first stage whose job is to download and start other malware.',
    'Attack framework': 'A professional hacking toolkit. Security teams use these legally for testing, and criminals use them in real attacks.',
    'Password tool': 'Pulls passwords and login tokens out of Windows memory. Used by testers and by attackers moving through a network.',
    'Destructive trojan': 'Built to damage the computer rather than make money, for example by making it unable to start.',
    'DDoS trojan': 'Turns your PC into part of a network that floods websites with traffic to knock them offline.',
    'Remote access tool': 'Remote control software with legitimate uses that is also widely abused by attackers.',
    Malware: 'Malicious software that does not fit neatly into one category.',
    'Kernel trojan': 'Malware that runs as a driver, at the deepest level of Windows.',
    Wiper: 'Destroys data or stops a PC from starting. There is usually no way to get anything back.',
    'Banking trojan': 'Steals online banking logins, often by changing what you see in your browser.',
    'Attack tool': 'A tool for breaking into or moving through networks, used by both security testers and attackers.',
    Rootkit: 'Hides itself and other malware deep inside the system so it is hard to find.',
  };

  const FAMILIES = [
    // ---- Remote access trojans ----
    { name: 'NanoCore', type: 'Remote access trojan', conf: 'strong', need: 2, verified: true,
      about: 'A long-running trojan sold cheaply online. It lets the attacker watch your screen, record your keys, steal passwords and use your webcam. It usually arrives through email attachments.',
      strings: ['nanocore.clientplugin', 'nanocore client', 'iclientlogginghost', 'iclientapphost', 'clientloaderform.resources', 'logclientexception'] },
    { name: 'NeptuneRAT', type: 'Remote access trojan', conf: 'possible', need: 1,
      about: 'A newer .NET trojan shared openly on GitHub, also seen under the Mason name. Reports show it using scheduled tasks to stay on the PC, taking screenshots and reporting back to an attacker\'s server.',
      strings: ['neptunerat', 'neptune rat', 'masonrat', 'masonusb.exe'] },
    { name: 'Remcos', type: 'Remote access trojan', conf: 'strong', need: 2, verified: true,
      about: 'Sold as a "remote control" product but constantly used in phishing attacks. It records keystrokes, audio and screenshots, and it gives full control of the PC.',
      strings: ['remcos restarted by watchdog!', 'mutex_remwatchdog', '* remcos v', 'remcos agent initialized (', '[chrome storedlogins found, cleared!]', 'uploading file to controller: '] },
    { name: 'AsyncRAT', type: 'Remote access trojan', conf: 'possible', need: 2,
      about: 'An open-source trojan written in C#. Because the code is free, many criminals reuse it, often as a later stage in larger attacks.',
      strings: ['asyncclient', 'asyncrat'] },
    { name: 'njRAT', type: 'Remote access trojan', conf: 'strong', need: 3, verified: true,
      about: 'An old, very widely copied trojan, also called Bladabindi. It logs keys, steals passwords, spreads over USB drives and opens remote control of the PC.',
      strings: ['cmd.exe /c ping 0 -n 2 & del "', 'netsh firewall delete allowedprogram "', '[+] system : ', 'download error'] },
    { name: 'DCRat', type: 'Remote access trojan', conf: 'strong', need: 1, verified: true,
      about: 'A cheap .NET trojan, also called DarkCrystal, with add-on plugins. It steals data, records the screen and keyboard, and gives remote control.',
      strings: ['dcratbyqwqdanchun', 'dcrat by qwqdanchun'] },
    { name: 'XWorm', type: 'Remote access trojan', conf: 'strong', need: 3, verified: true,
      about: 'A popular .NET trojan sold online. It can control the PC, steal data, run other malware, and spread through USB drives.',
      strings: ['<xwormmm>', 'activatepong', 'reportwindow', 'connectserver', 'openhide', 'hidefolderfile'] },
    { name: 'Warzone (Ave Maria)', type: 'Remote access trojan', conf: 'strong', need: 2, verified: true,
      about: 'A commercial trojan with hidden remote desktop access, password theft and tricks for getting admin rights without a prompt.',
      strings: ['warzone160', 'ave_maria stealer', 'accounts\\account.rec0', '/n:%temp%\\ellocnak.xml', 'hey i\'m admin', 'software\\_rptls', 'commandhandler::handlestartvnccommand'] },
    { name: 'Gh0st RAT', type: 'Remote access trojan', conf: 'strong', need: 4, verified: true,
      about: 'A classic trojan whose source code leaked years ago. Many variants exist, and it is known for espionage. It gives full control, including screen, keyboard and microphone.',
      strings: [':]%d-%d-%d  %d:%d:%d', '[pause break]', 'f-secure.exe', 'accept-language: zh-cn'] },
    { name: 'PlugX', type: 'Remote access trojan', conf: 'strong', need: 3, verified: true,
      about: 'A modular espionage trojan used for over a decade, largely in targeted attacks. Some versions spread through USB drives.',
      strings: ['eaddr:0x%p', 'host: [%s:%d]', '\\bug.log', 'ecode: 0x%p,', 'security wifi script', 'software\\classes\\ms-pu'] },
    { name: 'Quasar', type: 'Remote access tool', conf: 'possible', need: 2, verified: true,
      about: 'An open-source remote administration tool for Windows. It has real uses, but attackers often abuse it because it is free and full-featured. Check whether you installed it on purpose.',
      strings: ['getkeyloggerlogsresponse', 'dodownloadandexecute', '" /sc onlogon /tr "', 'domain: {1}{0}cookie name: {2}{0}value: {3}'] },

    // ---- Info stealers ----
    { name: 'SalatStealer', type: 'Info stealer', conf: 'strong', need: 1,
      about: 'A Go stealer rented out to criminals and also known as WEB_RAT. It targets browsers, crypto wallets and Telegram sessions, and it lets the operator run commands live. It is often UPX-packed, which can hide its text from PEek.',
      strings: ['webrat.in', 'webrat.top', 'webrat.su', 'webrat.ru', 'nyash.team', 'salat.cn'],
      hashes: ['8b94f5fa94f35e5ba47ce260b009b34401c5c54042d7b7252c8c7d13bf8d9f05', '552e1c2ed502f652d5cd1c70fee7a81d0269d1ad6db96ad21344ff4e1e3620d5'] },
    { name: 'AgentTesla', type: 'Info stealer', conf: 'strong', need: 3, verified: true,
      about: 'One of the most common stealers in email attacks. It records keys, takes screenshots and steals saved passwords, then sends them out by email, FTP or Telegram.',
      strings: ['getmozillafromlogins', 'getmozillafromsqlite', 'safaridecryptor', 'mozillabrowserlist', 'enablescreenlogger', 'publicipaddressgrab', 'enabletorpanel', 'vaultgetitem_win7', 'proxy-agent: htos5x'] },
    { name: 'RedLine', type: 'Info stealer', conf: 'strong', need: 1, verified: true,
      about: 'A hugely popular stealer rented to criminals, often hidden in fake cracks and game cheats. It takes browser logins, cookies, crypto wallets and Discord and Telegram data.',
      strings: ['redline.logic.sqlite', 'redline.reburn.data.browsers.gecko', 'redline.client.models.gecko'] },
    { name: 'Vidar', type: 'Info stealer', conf: 'strong', need: 3, verified: true,
      about: 'A stealer rented to criminals that collects passwords, cookies, card details and crypto wallets. It often finds its control server through social media profiles.',
      strings: ['%drive_fixed%', '%drive_removable%', 'file grabber rules', 'wallet rules', '_0.indexeddb.leveldb', '\\telemetry.b64'] },
    { name: 'Stealc', type: 'Info stealer', conf: 'strong', need: 2, verified: true,
      about: 'A lightweight stealer sold on criminal forums. It grabs browser data, wallets and email accounts, then deletes itself.',
      strings: ['c:\\builder_v2\\stealc\\json.h', '\\outlook\\accounts.txt', '- country: iso?', '/c timeout /t 5 & del /f /q'] },
    { name: 'Rhadamanthys', type: 'Info stealer', conf: 'strong', need: 2, verified: true,
      about: 'An advanced stealer rented to criminals, with a multi-stage design that makes it hard to analyze. It goes after passwords, wallets and password managers.',
      strings: ['tequilaboomboom', '%%appdata%%\\vcredist_%05x.dll', '%%temp%%\\vcredist_%05x.dll', '/bin/keepasshax.dll', '%%appdata%%\\ns%04x.dll', '%s\\tdata\\key_datas'] },
    { name: 'Lokibot', type: 'Info stealer', conf: 'strong', need: 1, verified: true,
      about: 'A long-lived stealer spread by email. It takes passwords from browsers, FTP apps and email clients, along with crypto wallets.',
      strings: ['mac=%02x%02x%02xinstall=%08x%08xk'] },
    { name: 'Lumma', type: 'Info stealer', conf: 'possible', need: 1,
      about: 'A very widespread stealer rented to criminals, known for fake CAPTCHA pages that trick people into running it. It targets passwords, session cookies and crypto wallets.',
      strings: ['lummac2'] },
    { name: 'Formbook', type: 'Info stealer',
      about: 'A cheap stealer and keylogger that grabs what you type into web forms.' },

    // ---- Ransomware ----
    { name: 'WannaCry', type: 'Ransomware', conf: 'strong', need: 2, verified: true,
      about: 'The ransomware behind the huge 2017 outbreak, which hit hospitals and companies worldwide. It encrypted files and spread by itself across networks.',
      strings: ['@wanadecryptor@.exe', '$%d worth of bitcoin', 'this folder protects against ransomware', 'wncry@2ol7', 'mssecsvc.exe', 'tasksche.exe'] },
    { name: 'LockBit', type: 'Ransomware', conf: 'strong', need: 2, verified: true,
      about: 'One of the most active ransomware groups of recent years. Partners break into companies, steal data, encrypt everything, then threaten to publish it.',
      strings: ['\\lockbit_ransomware.hta', 'classes\\lockbit\\shell', 'lockbit 3.0 the world', 'restore-my-files.txt', 'http://lockbit'] },
    { name: 'Ryuk', type: 'Ransomware', conf: 'strong', need: 1, verified: true,
      about: 'Targeted ransomware aimed at big organizations such as hospitals. It was usually deployed by hand after attackers had already broken in.',
      strings: ['ryukreadme.'] },

    // ---- Destructive ----
    { name: 'MEMZ', type: 'Destructive trojan', conf: 'strong', need: 1,
      about: 'A famous joke trojan that was made for a YouTube series. It fills the screen with effects, then overwrites the boot record, so the PC can no longer start.',
      strings: ['memz trojan'] },

    // ---- Backdoors & loaders ----
    { name: 'VShell', type: 'Backdoor',
      about: 'An open-source Go backdoor shared by several intrusion groups and known for running only in memory on Linux servers. PEek can only spot two exact known files, so a miss means little.',
      hashes: ['8d88944149ea1477bd7ba0a07be3a4371ba958d4a47b783f7c10cbe08c5e7d38', 'f064fdd24c56f2d20f1a6a32fc7edbd3848f962b25965b788b0dc725eeab9db4'] },
    { name: 'SNOWLIGHT', type: 'Loader', conf: 'strong', need: 3,
      about: 'A Linux dropper that fetches VShell and runs it directly from memory, disguised as a Linux system process.',
      strings: ['get /?a=%s&h=%s&t=%s&p=%d', '[kworker/0:2', 'user-agent: mozilla/5.0 (windows nt 6.1; rv:48.0) gecko/20100101 firefox/48.0'],
      hashes: ['e6db3de3a21debce119b16697ea2de5376f685567b284ef2dee32feb8d2d44f8', '6579defcd1326efad359c59cfe9a76d7df375e54f6e977dd880d10f81325999e'] },
    { name: 'Amadey', type: 'Loader', conf: 'strong', need: 1, verified: true,
      about: 'A small bot that reports on the infected PC and downloads other malware such as stealers. PEek uses one known build path, so most samples will not match.',
      strings: ['d:\\mktmp\\nl1\\release\\nl1.pdb'] },

    // ---- Attack tools ----
    { name: 'Cobalt Strike', type: 'Attack framework', conf: 'strong', need: 2, verified: true,
      about: 'A commercial tool for testing company defenses. Cracked copies are one of the most common tools in real attacks, especially before ransomware.',
      strings: ['beacon.x64.dll', 'beacon.dll', 'i\'m already in smb mode', 'ppid %d is in a different desktop session', 'could not run command (w/ token)', 'z:\\devcenter\\aggressor\\'] },
    { name: 'Meterpreter', type: 'Attack framework', conf: 'strong', need: 2, verified: true,
      about: 'The remote control payload from Metasploit, the best-known hacking toolkit. It is used by testers and attackers and is often injected straight into memory.',
      strings: ['metsrv.x64.dll', 'metsrv.dll', 'packet transmit'] },
    { name: 'Brute Ratel', type: 'Attack framework', conf: 'strong', need: 3, verified: true,
      about: 'A commercial testing toolkit built to avoid security products. Leaked copies have been used by real attackers.',
      strings: ['[+] spoofed ppid => %lu', '[-] child process not set', '[+] crisis monitor: already running', '[+] added socks profile', '[+] token removed', '[tasks] %02d => 0x%02x 0x%02x', '_imp_badgerdispatch', '_imp_badgerstrlen', '_imp_badgermemcpy'] },
    { name: 'Mimikatz', type: 'Password tool', conf: 'strong', need: 2, verified: true,
      about: 'A well-known tool that pulls passwords and login tickets out of Windows memory. Security testers use it, but on a normal home PC it is a serious warning sign.',
      strings: ['gentilkiwi', 'mimikatz(commandline) # %s', 'log mimikatz input/output to file', 'sekurlsa::'] },

    // ---- Other ----
    // The text markers are a guess at how the "Unicorn-[number].exe" names from sandbox reports are stored.
    { name: 'KawaiiUnicorn', type: 'Malware', conf: 'possible', need: 1,
      about: 'Yes, it is a real name. Sandbox reports describe a Windows program that floods the PC with randomly numbered "Unicorn" processes and drops copies of itself to make cleanup harder, and one vendor labels it a keylogger and virus. Public details are thin. PEek knows two exact files, plus a name pattern that has not been checked against a real sample.',
      strings: ['unicorn-%d.exe', 'unicorn-%u.exe', 'unicorn-%i.exe'],
      hashes: ['2428265dbf3afa15f6da7c56233dace4ff0ba2700e4cd7c9e8330edfb5cd794b', '45c31557c2fd01d44cdec92dcc2dd85c9c114648bd069cf24e7ae9f1786d2c03'] },
    { name: 'Stormser', type: 'DDoS trojan',
      about: 'A Windows worm written in C++, also called StormDDoS and StormAttack, used to flood websites with traffic. PEek can only spot one exact known file, so a miss means little.',
      hashes: ['792c7f6c04ae2d83bcc8b4b228b546e79807a9c09d6773f1f94775e815f85d50'] },
    { name: 'Systex', type: 'Kernel trojan',
      about: 'A Microsoft detection name (Trojan:WinNT/Systex.A) with almost no public detail. The name suggests a kernel-level trojan. PEek has no signature for it yet.' },
  ];

  function match(f, sha256) {
    const out = [];
    for (const fam of FAMILIES) {
      const base = { name: fam.name, type: fam.type, about: fam.about };
      if (sha256 && fam.hashes && fam.hashes.includes(sha256)) {
        out.push({ ...base, conf: 'exact', evidence: ['SHA-256 matches a known sample'] });
        continue;
      }
      if (!fam.strings) continue;
      const hits = fam.strings.filter((s) => f.low.includes(s));
      // Text files can merely talk about a family, so only a program can be a strong match.
      if (hits.length >= fam.need) out.push({ ...base, conf: f.kind === 'script' ? 'possible' : fam.conf, evidence: hits });
    }
    return out;
  }

  root.PEek = root.PEek || {};
  root.PEek.families = { match, FAMILIES, TYPES };
})(typeof window !== 'undefined' ? window : globalThis);
