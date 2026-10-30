/*
 * PEek — tags.js
 * Classifies a file with uppercase tags, in two groups:
 *   type      what the file is, e.g. RAT or RANSOMWARE
 *   behavior  what it does, e.g. DISCOVERY or PERSISTENCE
 * Each test gets { any, has, family, value }: rule ids that fired, tags implied by matched families,
 * and the 0-10 rating. The same data drives the Malware guide page.
 */
(function (root) {
  'use strict';

  // What each family type counts as.
  const FAMILY_TAGS = {
    'Remote access trojan': ['TROJAN', 'RAT'], 'Info stealer': ['STEALER'], Ransomware: ['RANSOMWARE'], Backdoor: ['BACKDOOR'], Loader: ['LOADER'],
    'Attack framework': ['HACKTOOL'], 'Password tool': ['HACKTOOL'], 'Destructive trojan': ['TROJAN', 'WIPER'], 'DDoS trojan': ['DDOS'],
    'Remote access tool': ['RISKWARE'], Malware: ['TROJAN'], 'Kernel trojan': ['ROOTKIT'],
    Wiper: ['WIPER'], 'Banking trojan': ['TROJAN', 'STEALER'], 'Attack tool': ['HACKTOOL'], Rootkit: ['ROOTKIT'],
  };

  const TAGS = [
    // ---- Types ----
    { tag: 'TROJAN', group: 'type', about: 'Pretends to be something useful or harmless while doing something else.',
      how: 'A disguise was found, such as a fake extension or a fake company name, or the threat score is 7 or higher.',
      test: (c) => c.any('fake-extension', 'risky-extension', 'brand-impersonation', 'system-name') || c.value >= 7 },
    { tag: 'RAT', group: 'type', about: 'A remote access trojan. It gives someone else control of your PC, usually including your screen, files and keyboard.',
      how: 'A known RAT family matched, or a remote command line appears together with spying abilities.',
      test: (c) => (c.has('reverse-shell') && c.any('keylogger', 'webcam', 'screenshot')) || (c.has('dotnet-config') && c.any('dotnet-remote-control', 'keylogger')) },
    { tag: 'WORM', group: 'type', about: 'Copies itself to other computers on its own, often through USB drives or networks.',
      how: 'Code for spreading through USB drives or network shares was found.',
      test: (c) => c.any('usb-spread', 'network-spread') },
    { tag: 'RANSOMWARE', group: 'type', about: 'Encrypts your files and demands money to unlock them.',
      how: 'A ransom note was found, or it deletes backups and can also encrypt files.',
      test: (c) => c.has('ransom-note') || (c.has('delete-backups') && c.has('encrypts-files')) },
    { tag: 'STEALER', group: 'type', about: 'Takes saved passwords, cookies, crypto wallets and app logins, then sends them to the attacker.',
      how: 'It targets browser data, wallets or app logins, or a known stealer family matched.',
      test: (c) => c.any('browser-stealer', 'wallet-stealer', 'discord-stealer', 'telegram-stealer', 'app-credentials', 'clipper') },
    { tag: 'SPYWARE', group: 'type', about: 'Secretly watches what you do and reports it.',
      how: 'Keyboard recording or webcam capture code was found.',
      test: (c) => c.any('keylogger', 'webcam') },
    { tag: 'KEYLOGGER', group: 'type', about: 'Records everything you type, including passwords.',
      how: 'It watches the keyboard globally, converts keys to text and tracks the active window.',
      test: (c) => c.has('keylogger') },
    { tag: 'BACKDOOR', group: 'type', about: 'Keeps a hidden way into a computer so someone can come back later.',
      how: 'A remote command line was found, or a known backdoor family matched.',
      test: (c) => c.has('reverse-shell') },
    { tag: 'LOADER', group: 'type', about: 'A small program that downloads and starts the real malware.',
      how: 'It downloads and runs files or code, abuses Windows tools to do so, or a known loader matched.',
      test: (c) => c.any('downloader', 'lolbins', 'script-dropper', 'fileless', 'memory-loader') },
    { tag: 'DROPPER', group: 'type', about: 'Carries malware inside itself and unpacks it onto your PC.',
      how: 'A script hides a Windows program, or a program hides another one and also injects code or sets itself to start with Windows.',
      test: (c) => c.has('script-embedded-exe') || (c.has('embedded-exe') && c.any('injection', 'hollowing', 'autorun', 'scheduled-task')) },
    { tag: 'CRYPTINJECT', group: 'type', about: 'Hides inside an encrypted wrapper, then injects the real malware into another program. The wrapper is why antivirus often misses it.',
      how: 'Packed or encrypted content appears together with code injection or process hollowing.',
      test: (c) => c.any('packed', 'protector', 'encrypted-blob') && c.any('injection', 'hollowing') },
    { tag: 'TROJANCRYPTINJECT', group: 'type', about: 'A trojan built around an encrypted wrapper. It disguises itself or looks strongly malicious, and it injects its hidden code into another program.',
      how: 'It matches CRYPTINJECT and also shows a disguise or has a threat score of 7 or higher.',
      test: (c) => c.any('packed', 'protector', 'encrypted-blob') && c.any('injection', 'hollowing')
        && (c.any('fake-extension', 'risky-extension', 'brand-impersonation', 'system-name') || c.value >= 7) },
    { tag: 'MINER', group: 'type', about: 'Uses your CPU or GPU to mine cryptocurrency for someone else.',
      how: 'Mining pool addresses or miner settings were found.',
      test: (c) => c.has('miner') },
    { tag: 'WIPER', group: 'type', about: 'Built to destroy data or stop a PC from working, not to make money.',
      how: 'It can overwrite the boot record, or a known destructive family matched.',
      test: (c) => c.has('boot-overwrite') },
    { tag: 'BOOTKIT', group: 'type', about: 'Tampers with the code that starts your PC, before Windows even loads.',
      how: 'It can write to the first disk and also has other destructive abilities.',
      test: (c) => c.has('boot-overwrite') },
    { tag: 'ROOTKIT', group: 'type', about: 'Hides deep inside Windows so that files, processes and even itself become invisible.',
      how: 'A driver touches internal kernel tables that rootkits commonly change.',
      test: (c) => c.has('kernel-tamper') },
    { tag: 'DDOS', group: 'type', about: 'Uses your PC to flood websites with traffic and knock them offline.',
      how: 'Several website flooding attack names were found.',
      test: (c) => c.has('ddos') },
    { tag: 'BOTNET', group: 'type', about: 'Makes your PC one of many machines taking orders from the same controller.',
      how: 'IRC command text was found. This is a weak sign on its own, because real chat apps contain it too.',
      test: (c) => c.has('irc-bot') },
    { tag: 'ADWARE', group: 'type', about: 'Pushes ads or unwanted browser changes on you.',
      how: 'It mentions the policy that forces browser extensions onto a PC.',
      test: (c) => c.has('force-extension') },
    { tag: 'HACKTOOL', group: 'type', about: 'A tool for attacking systems, used by both security testers and criminals.',
      how: 'A known attack tool such as Mimikatz or Cobalt Strike matched.',
      test: () => false },
    { tag: 'GAME_CHEAT', group: 'type', about: 'Changes how a game works. It can get your account banned, and fake cheats often hide real malware.',
      how: 'At least two cheat words or game memory names were found.',
      test: (c) => c.has('game-cheat') },
    { tag: 'CHEAT_INJECTOR', group: 'type', about: 'A tool that loads cheat code into a running game. It can get your account banned, and many downloads of these tools hide real malware.',
      how: 'It looks like a DLL injector, or it has both game cheat signs and code injection abilities.',
      test: (c) => c.has('injector-tool') || (c.has('game-cheat') && c.has('injection')) },
    { tag: 'RISKWARE', group: 'type', about: 'Not clearly malware, but it can be abused or put your PC at risk. Check that you meant to have it.',
      how: 'It has powerful abilities such as changing other programs\' memory, and no stronger type applies.',
      test: (c) => c.any('memory-access', 'debug-privilege', 'raw-disk', 'driver', 'hosts-file', 'firewall', 'network-spread', 'game-cheat') },

    // ---- Behaviors ----
    { tag: 'DISCOVERY', group: 'behavior', about: 'Gathers information about the PC, user or network.',
      how: 'Several system information commands or queries were found.',
      test: (c) => c.has('discovery') },
    { tag: 'EXECUTION', group: 'behavior', about: 'Runs other code, scripts or commands.',
      how: 'It runs downloads, hidden PowerShell or injected code.',
      test: (c) => c.any('downloader', 'powershell', 'lolbins', 'script-dropper', 'injection', 'hollowing', 'fileless', 'memory-loader') },
    { tag: 'PERSISTENCE', group: 'behavior', about: 'Sets itself up to keep running after a restart.',
      how: 'It uses startup entries, scheduled tasks or services.',
      test: (c) => c.any('autorun', 'scheduled-task', 'startup-hijack', 'service') },
    { tag: 'DEFENSE_EVASION', group: 'behavior', about: 'Avoids or disables security tools.',
      how: 'It targets Defender, kills antivirus, checks for analysis tools or hides its code or text.',
      test: (c) => c.any('dotnet-obfuscated', 'defender-off', 'block-tools', 'kill-av', 'firewall', 'anti-analysis', 'packed', 'signature-broken', 'motw', 'encoded-strings', 'hidden-strings', 'script-obfuscated', 'amsi-bypass') },
    { tag: 'PRIVILEGE_ESCALATION', group: 'behavior', about: 'Tries to gain more rights than it was given.',
      how: 'UAC bypass tricks or special debug privileges were found.',
      test: (c) => c.any('uac-bypass', 'debug-privilege') },
    { tag: 'EXFILTRATION', group: 'behavior', about: 'Sends data out to the attacker.',
      how: 'A Discord webhook or Telegram bot was found.',
      test: (c) => c.any('discord-webhook', 'telegram-bot') },
    { tag: 'DESTRUCTIVE', group: 'behavior', about: 'Can cause real damage to your PC or data.',
      how: 'It can overwrite the boot record, crash Windows or delete backups.',
      test: (c) => c.any('boot-overwrite', 'bsod', 'delete-backups', 'ransom-note') },
  ];

  const STRONGER = TAGS.filter((t) => t.group === 'type' && !['GAME_CHEAT', 'CHEAT_INJECTOR', 'RISKWARE'].includes(t.tag)).map((t) => t.tag);

  function classify({ fired, families, value, signed }) {
    const fromFamilies = new Set(families.flatMap((x) => FAMILY_TAGS[x.type] || []));
    const c = { has: (id) => fired.has(id), any: (...ids) => ids.some((id) => fired.has(id)), value };
    const found = new Set(TAGS.filter((t) => fromFamilies.has(t.tag) || t.test(c)).map((t) => t.tag));
    if (STRONGER.some((t) => found.has(t))) found.delete('RISKWARE');
    if (found.has('TROJANCRYPTINJECT')) found.delete('CRYPTINJECT');    // the more specific tag covers it
    // Attack tools are openly what they are, so a high score alone does not make one a trojan.
    if (found.has('HACKTOOL') && !c.any('fake-extension', 'brand-impersonation', 'system-name')) found.delete('TROJAN');
    // Signed software really has these abilities, so a type label would be misleading.
    const list = TAGS.filter((t) => found.has(t.tag));
    return (signed ? list.filter((t) => t.group === 'behavior') : list).map((t) => t.tag);
  }

  root.PEek = root.PEek || {};
  root.PEek.tags = { classify, TAGS };
})(typeof window !== 'undefined' ? window : globalThis);
