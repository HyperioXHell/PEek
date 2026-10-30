/*
 * PEek - families-more.js
 * More malware families, added to the list in families.js. Text markers come from Elastic's public
 * YARA rules (elastic/protections-artifacts), keeping only the literal text, which matches less
 * precisely than the full rules. Markers seen in about 190 normal programs were removed.
 */
(function (root) {
  'use strict';
  root.PEek.families.FAMILIES.push(...[
    {
        "name":  "Akira",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A ransomware group active since 2023 that breaks into companies, steals data and encrypts files, then threatens to publish what it took.",
        "strings":  [
                        "akira_readme.txt",
                        "number of threads to encrypt = ",
                        "write_encrypt_info error:",
                        "log-%d-%m-%y-%h-%m-%s",
                        "--encryption_path",
                        "--encryption_percent"
                    ]
    },
    {
        "name":  "Black Basta",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A ransomware group that targeted large organizations, using stolen data as extra pressure to make victims pay.",
        "strings":  [
                        "done time: %.4f seconds, encrypted: %.4f gb",
                        "creating readme at %s",
                        "all of your files are currently encrypted by no_name_software.",
                        "don't move or rename your files. these parameters can be used for encryption/decryption process.",
                        "your data are stolen and encrypted",
                        "bcdedit /deletevalue safeboot",
                        "your company id for log in:"
                    ]
    },
    {
        "name":  "Black Hunt",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "Ransomware that encrypts files and drops its own ransom notes on infected PCs.",
        "strings":  [
                        "#blackhunt_readme.txt",
                        "#blackhunt_private.key",
                        "#blackhunt_id.txt",
                        "black_hunt_mutex",
                        "encrypted volume : %dgb",
                        "running time : %02dm:%02ds"
                    ]
    },
    {
        "name":  "Agenda (Qilin)",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "Ransomware rented out to criminal partners, also known as Qilin, and often customized for each victim.",
        "strings":  [
                        "-recover-readme.txt",
                        "/c vssadmin.exe delete shadows /all /quiet",
                        "directory_black_list",
                        "c:\\users\\public\\enc.exe"
                    ]
    },
    {
        "name":  "Cuba",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "Ransomware that has hit critical organizations and also steals data before encrypting it.",
        "strings":  [
                        "we also inform that your databases, ftp server and file server were downloaded by us to our servers.",
                        "good day. all your files are encrypted. for decryption contact us."
                    ]
    },
    {
        "name":  "DragonForce",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A ransomware operation that lets partners run attacks under its name and threatens to leak stolen data.",
        "strings":  [
                        "%04d-%02d-%02dt%02d:%02d:00z",
                        ".dragonforce_encrypted"
                    ]
    },
    {
        "name":  "Everest",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A ransomware and data extortion group that sells or leaks stolen data.",
        "strings":  [
                        "everestransomware.txt",
                        "greetings from the everest team."
                    ]
    },
    {
        "name":  "HelloKitty",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "Ransomware known for targeting companies, including a well-known attack on a game developer. Its source code later leaked.",
        "strings":  [
                        "hellokittymutex",
                        "win32_shadowcopy.id='%s'",
                        "trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!",
                        "decrypt_note.txt",
                        "some data has been stored in our servers and ready for publish.",
                        "to contact with us you have one week from the encryption time, after decryption keys and your personal contact link will be dele",
                        "in case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing.",
                        "important: don't modify encrypted files or you can damage them and decryption will be impossible!",
                        "/f /im \"%s\""
                    ]
    },
    {
        "name":  "Hive",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A major ransomware service that was taken down by law enforcement in 2023 after hitting hospitals and companies.",
        "strings":  [
                        "bmr|sql|oracle|postgres|redis|vss|backup|sstp",
                        "killing processes",
                        "stopping services",
                        "removing itself"
                    ]
    },
    {
        "name":  "INC",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A ransomware group that steals data and encrypts files, often hitting healthcare and businesses.",
        "strings":  [
                        "couldn't delete shadow copies from",
                        "--file <file>",
                        "--safe-mode",
                        "starting full encryption in 5s"
                    ]
    },
    {
        "name":  "LockFile",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Ransomware known for encrypting only parts of files, which helps it dodge detection.",
        "strings":  [
                        "lockfile-readme",
                        "wmic process where \"name  like '%virtualbox%'\" call terminate",
                        "</computername>"
                    ]
    },
    {
        "name":  "Maui",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "Ransomware that US agencies linked to North Korean attacks on healthcare organizations.",
        "strings":  [
                        "please append it by <godhead> using -maui option.",
                        "please overwrite it by <godhead> using -maui option.",
                        "encrypt[%s]: %s",
                        "process_goingon[%d%% / %d%%]: %s",
                        "process_replaceconfirm: %s"
                    ]
    },
    {
        "name":  "Medusa",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A ransomware service that threatens to publish stolen data on a public leak site.",
        "strings":  [
                        "kill_processes %s",
                        "kill_services %s",
                        ":note path = %s",
                        "write note file error:%s",
                        "rename file error:%s"
                    ]
    },
    {
        "name":  "Mespinoza (PYSA)",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "Ransomware also known as PYSA, known for attacks on schools and governments.",
        "strings":  [
                        "don't try to use backups because it were encrypted too.",
                        "every byte on any types of your devices was encrypted."
                    ]
    },
    {
        "name":  "MountLocker",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Ransomware that steals data before encrypting and later changed names several times.",
        "strings":  [
                        "[skip] locker.dir.check > black_list name=%s",
                        "[ok] locker.dir.check > name=%s",
                        "[error] locker.worm > execute pcname=%s",
                        "[info] locker.work.enum.net_drive > enum finish name=%s",
                        "[warn] locker.work.enum.server_shares > logon on server error=%u pcname=%s"
                    ]
    },
    {
        "name":  "Nefilim",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Ransomware that targets large companies and threatens to release stolen data.",
        "strings":  [
                        "nefilim-decrypt.txt",
                        "oh how i did it??? bypass sofos hah",
                        "timeout /t 3 /nobreak && del",
                        "ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'"
                    ]
    },
    {
        "name":  "NightSpire",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A newer ransomware group that steals data and encrypts files.",
        "strings":  [
                        "by nightspire.team",
                        ">>> using qtox chat app",
                        "/[nspire_msg].txt",
                        "answer.nspire",
                        "change the icon of nspire file",
                        "main.makereadmefile",
                        "main.writetotail",
                        "main.checkpossibility",
                        "nightspireteam",
                        "specify the encryption method."
                    ]
    },
    {
        "name":  "Night Sky",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A short-lived ransomware that targeted companies and used double extortion.",
        "strings":  [
                        "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">night sky</span></center>",
                        "url:https://contact.nightsky.cyou"
                    ]
    },
    {
        "name":  "RansomEXX",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "Ransomware used in targeted attacks on governments and large companies.",
        "strings":  [
                        "ransom.exx",
                        "infrastructure rebuild will cost you much more.",
                        "your files are securely encrypted.",
                        "delete catalog -quiet"
                    ]
    },
    {
        "name":  "Royal",
        "type":  "Ransomware",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A private ransomware group that hit critical infrastructure and later rebranded as BlackSuit.",
        "strings":  [
                        "try royal today and enter the new era of data security",
                        "if you are reading this, it means that your system were hit by royal ransomware."
                    ]
    },
    {
        "name":  "VGOD",
        "type":  "Ransomware",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Ransomware that encrypts files and demands payment. Public details are limited.",
        "strings":  [
                        "vgod-ransomware/configuration.init",
                        "vgod-ransomware/encryption.encryptfile",
                        "/vgod-ransomware/vgod-ransomware/encryptor/encryption/encryption.go",
                        "main.removebuiltexe",
                        "contact mail: vgod@ro.ru",
                        "vgod-built.exe",
                        "indicate your id and if you want attach 2-3 infected files to generate a private key and compile the decryptor"
                    ]
    },
    {
        "name":  "HermeticWiper",
        "type":  "Wiper",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A destructive wiper used against Ukrainian organizations in 2022. It corrupts disks so that PCs cannot start.",
        "strings":  [
                        "\\\\.\\epmntdrv\\%u",
                        "hermetica digital"
                    ]
    },
    {
        "name":  "IsaacWiper",
        "type":  "Wiper",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A wiper used in attacks on Ukraine in 2022. It destroys data on disks and files.",
        "strings":  [
                        "c:\\programdata\\log.txt",
                        "system physical drive -- failed",
                        "-- system logical drive: ",
                        "start erasing system logical drive ",
                        "-- logical drive: ",
                        "-- start erasing logical drive "
                    ]
    },
    {
        "name":  "DoubleZero",
        "type":  "Wiper",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A .NET wiper used against Ukrainian targets that overwrites files with zeros.",
        "strings":  [
                        "\\users\\\\.*?\\\\local settings.*",
                        "get__beba00adeeb086e6",
                        "filesharewrite"
                    ]
    },
    {
        "name":  "WhisperGate",
        "type":  "Wiper",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Destructive malware disguised as ransomware, used against Ukraine in 2022. Its ransom note is fake and data cannot be recovered.",
        "strings":  [
                        "dxownxloxaddxatxxax",
                        "-enc uwb0ageacgb0ac",
                        "ylfwdwgmpilzyaph"
                    ]
    },
    {
        "name":  "Babylon RAT",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A commercial trojan with keylogging, password theft and remote control.",
        "strings":  [
                        "babylonrat",
                        "babylon rat client",
                        "ping 0 & del \"",
                        "\\%y %m %d - %i %m %p"
                    ]
    },
    {
        "name":  "BitRAT",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A trojan sold on criminal forums, with hidden remote desktop, keylogging and crypto mining.",
        "strings":  [
                        "crd_logins_report",
                        "drives_get",
                        "shell_stop",
                        "hvnc_start_ie"
                    ]
    },
    {
        "name":  "BlackShades",
        "type":  "Remote access trojan",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "An infamous trojan whose sellers and users were arrested worldwide in 2014. It could spy through webcams and steal files.",
        "strings":  [
                        "*\\ad:\\blackshades project\\bs_net\\server\\server.vbp",
                        "@*\\ad:\\blackshades project\\bs_net\\server\\server.vbp",
                        "d:\\blackshades project\\bs_net\\loginserver\\msvbvm60.dll\\3",
                        "\\pws_chro.bss",
                        "tmrlivelogger"
                    ]
    },
    {
        "name":  "CyberGate",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A long-running trojan that gives full remote control of a PC.",
        "strings":  [
                        "ielogin.abc",
                        "xxxyyyzzz.dat",
                        "_x_x_passwordlist_x_x_",
                        "l$_rasdefaultcredentials#0",
                        "\\signons1.txt"
                    ]
    },
    {
        "name":  "DarkComet",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A famous trojan with webcam, keylogging and full control. Its developer stopped it after it was used in Syria.",
        "strings":  [
                        "btresulthttp flood|http flood task finished!|",
                        "is now open!|",
                        "activeonlinekeylogger",
                        "#bot#runprompt"
                    ]
    },
    {
        "name":  "DarkGate",
        "type":  "Loader",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "Malware sold as a service, with remote access, crypto mining and stealing, often spread through phishing.",
        "strings":  [
                        "darkgate has recovered from a critical error",
                        "executing darkgate inside the new desktop...",
                        "restart darkgate "
                    ]
    },
    {
        "name":  "LimeRAT",
        "type":  "Remote access trojan",
        "conf":  "possible",
        "need":  1,
        "verified":  true,
        "about":  "An open-source .NET trojan with ransomware, mining and stealing plugins.",
        "strings":  [
                        "schtasks /create /f /sc onlogon /rl highest /tn limerat-admin /tr \"'"
                    ]
    },
    {
        "name":  "NetWire",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A long-running trojan for spying and stealing. Its seller was arrested in 2023.",
        "strings":  [
                        "%6\\6z65dlnh\\yls.dfd",
                        "get %s http/1.1",
                        "r-w65: %6:%s",
                        "ptlljpq %6:%s -qq9/g.y"
                    ]
    },
    {
        "name":  "Parallax",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  7,
        "verified":  true,
        "about":  "A trojan sold online, with stealthy remote control and password theft.",
        "strings":  [
                        "clipboard start",
                        "[clipboard end]",
                        ".deletefile(wscript.scriptfullname)",
                        ".deletefolder",
                        ".deletefile ",
                        "scripting.filesystemobject",
                        "on error resume next",
                        "= createobject",
                        ".fileexists"
                    ]
    },
    {
        "name":  "RevCode (WebMonitor)",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "Remote access software sold as a monitoring tool, used widely as a trojan.",
        "strings":  [
                        "plugin_process_reverse_proxy: plugin already exists, skipping download!",
                        "webcam_activate: plugin already exists, skipping download!",
                        "send_keylog_get"
                    ]
    },
    {
        "name":  "STRRAT",
        "type":  "Remote access trojan",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A Java trojan that steals passwords and logs keys, and can pretend to be ransomware.",
        "strings":  [
                        "strigoi/server/ping.php?lid=",
                        "/strigoi/server/?hwid="
                    ]
    },
    {
        "name":  "XpertRAT",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A trojan for remote control and spying.",
        "strings":  [
                        "[xpertrat-mutex]",
                        "xpertplugin",
                        "keylog.tmp"
                    ]
    },
    {
        "name":  "Xtreme RAT",
        "type":  "Remote access trojan",
        "conf":  "strong",
        "need":  7,
        "verified":  true,
        "about":  "A trojan used in both crime and targeted attacks, with full remote control.",
        "strings":  [
                        "startserverbuffer",
                        "endserverbuffer",
                        "serverkeyloggeru",
                        "tserverkeylogger",
                        "xtremekeylogger",
                        "xtremebinder",
                        "unitinjectserver",
                        "shellexecute="
                    ]
    },
    {
        "name":  "Jester Stealer",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A stealer sold on forums that takes browser data, wallets and app logins.",
        "strings":  [
                        "[decrypt chrome password] {0}",
                        "9stealer.recovery.ftp.filezilla+<enumeratecredentials>d__0",
                        "/c chcp 65001 && ping 127.0.0.1 && del /f /s /q /a \"",
                        "citigroup.com",
                        "password: {1}"
                    ]
    },
    {
        "name":  "MassLogger",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A .NET stealer and keylogger sold online, spread through email.",
        "strings":  [
                        "executionpolicy bypass -windowstyle hidden -command netsh advfirewall firewall add rule name='allow remotedesktop' dir=in protoc",
                        "echo $smtpserver  = smtp.gmail.com >> %psscript%",
                        "injecting default template....",
                        "getvncloginmethodasync",
                        "/c start computerdefaults.exe"
                    ]
    },
    {
        "name":  "MetaStealer",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  6,
        "verified":  true,
        "about":  "A stealer that targets browser data and crypto wallets.",
        "strings":  [
                        "availablelanguages",
                        "getgraphiccards",
                        "antivirusproduct|antispywareproduct|firewallproduct",
                        "[a-za-z\\d]{24}\\.[\\w-]{6}\\.[\\w-]{27}",
                        "{0}\\filezilla\\sitemanager.xml",
                        "([a-za-z0-9]{1000,1500})"
                    ]
    },
    {
        "name":  "Oski Stealer",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A stealer that takes saved passwords, cookies and wallets.",
        "strings":  [
                        "\"os_crypt\":{\"encrypted_key\":\"",
                        "outlook.txt",
                        "glox6gmcfw==",
                        "kaoqpezksjgm8q=="
                    ]
    },
    {
        "name":  "Pony",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  6,
        "verified":  true,
        "about":  "A classic password stealer whose leaked source code was widely reused.",
        "strings":  [
                        "\\global downloader",
                        "wiseftpsrvs.bin",
                        "siteserver %d\\sftp",
                        "connections.txt",
                        "ftpshell.fsi",
                        "inetcomm server passwords"
                    ]
    },
    {
        "name":  "PureLogs",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A .NET stealer sold online that sends stolen data to its operators.",
        "strings":  [
                        "senddiscordasync",
                        "sendcryptowalletasync",
                        "collectandsendallasync",
                        "/filesearch/req",
                        "/filesearch/res",
                        "/chunk/data",
                        "/chunk/start"
                    ]
    },
    {
        "name":  "Raccoon Stealer",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A stealer rented to criminals that targets browser logins, cookies and wallets.",
        "strings":  [
                        "\\ffcookies.txt",
                        "0network\\cookies",
                        "wn0nldexjizjllkehyxnvtaxhxrtewg0iegkvyd52cvonbw7g91rvqdwszi/n2ism4xewrkyjwjnyugs9ozmj/taie8jg07execo8d7h2m2lgzwnfg31r1rsxg1+g8e="
                    ]
    },
    {
        "name":  "Snake Keylogger",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  8,
        "verified":  true,
        "about":  "A .NET keylogger and stealer spread through email attachments.",
        "strings":  [
                        "getoutlookpasswords",
                        "startkeylogger",
                        "keyloggereventargs",
                        "keyloggereventargseventhandler",
                        "getdatapassword",
                        "_encryptedpassword",
                        "----------------s--------n--------a--------k--------e----------------",
                        "snake-keylogger"
                    ]
    },
    {
        "name":  "StormKitty",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "An open-source stealer that also tries to block security websites.",
        "strings":  [
                        "127.0.0.1 www.malwarebytes.com",
                        "killdefender",
                        "username: {1}",
                        "# end of cookies",
                        "# end of passwords"
                    ]
    },
    {
        "name":  "Phemedrone",
        "type":  "Info stealer",
        "conf":  "strong",
        "need":  10,
        "verified":  true,
        "about":  "An open-source stealer that takes browser data, wallets and app sessions.",
        "strings":  [
                        "<killdebuggers>b_",
                        "<key3database>b_",
                        "<parsedatwallets>b_",
                        "<parseextensions>b_",
                        "<parsediscordtokens>b_",
                        "phemedrone.senders",
                        "phemedrone.protections",
                        "phemedrone.extensions",
                        "phemedrone.cryptography",
                        "phemedrone-report.zip"
                    ]
    },
    {
        "name":  "DanaBot",
        "type":  "Banking trojan",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A modular banking trojan and stealer sold to criminals.",
        "strings":  [
                        "del_ini://main|password|",
                        "s-password.txt",
                        "thttpinject&"
                    ]
    },
    {
        "name":  "Gozi (Ursnif)",
        "type":  "Banking trojan",
        "conf":  "strong",
        "need":  8,
        "verified":  true,
        "about":  "A very old banking trojan family, also called Ursnif, whose code has spawned many variants.",
        "strings":  [
                        "/c ping localhost -n %u && del \"%s\"",
                        "/c \"copy \"%s\" \"%s\" /y && \"%s\" \"%s\"",
                        "/c \"copy \"%s\" \"%s\" /y && rundll32 \"%s\",%s\"",
                        "ascii.getstring(( gp \"%s:\\%s\").%s))',0,0)",
                        "filename=\"%.4u.%lu\"",
                        "urundll32 \"%s\",%s",
                        "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s",
                        "%08x-%04x-%04x-%04x-%08x%04x",
                        "&whoami=%s",
                        "size=%u&hash=0x%08x"
                    ]
    },
    {
        "name":  "Kronos",
        "type":  "Banking trojan",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A banking trojan that injects fake forms into web pages to steal logins.",
        "strings":  [
                        "data_inject",
                        "d7t1h5f0f5a4c6s3"
                    ]
    },
    {
        "name":  "TrickBot",
        "type":  "Banking trojan",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A major banking trojan that grew into a platform for ransomware attacks.",
        "strings":  [
                        "[inject] inject_via_remotethread_wow64: pexecutex64( px64function, ctx ) failed",
                        "[inject] inject_via_remotethread_wow64: virtualalloc pexecutex64 failed",
                        "[inject] inject_via_remotethread_wow64: pexecutex64=0x%08p, px64function=0x%08p, ctx=0x%08p",
                        "dll and target process must be same architecture",
                        "[inject] inject_via_remotethread_wow64: virtualalloc px64function failed",
                        "wrote shellcode to 0x%x",
                        "error: %d, line - %d",
                        "[inject] inject_via_remotethread_wow64: success, hthread=0x%08p",
                        "getprocesspeb:except",
                        "checked count - %i, connected count %i"
                    ]
    },
    {
        "name":  "Zeus",
        "type":  "Banking trojan",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "The classic banking trojan. Its source code leaked and inspired many later families.",
        "strings":  [
                        "name=%s&port=%u",
                        "data_inject",
                        "keylog.txt"
                    ]
    },
    {
        "name":  "Bumblebee",
        "type":  "Loader",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A loader used to deliver ransomware and attack tools.",
        "strings":  [
                        "checking virtual pc processes %s ",
                        "injection-date",
                        " -command \"wait-process -id ",
                        "objshell.run \"rundll32.exe my_application_path",
                        "checking reg key hardware\\description\\system - %s is set to %s"
                    ]
    },
    {
        "name":  "Glupteba",
        "type":  "Loader",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A botnet malware that mines crypto, steals data and hides with a rootkit.",
        "strings":  [
                        "is unavailable%d smbtest",
                        "discovered new server %s",
                        "uldn't get usernamecouldn't hide servicecouldn't",
                        "terminate process: %ws, %d, %d",
                        "[+] extracting vulnerable driver as \"%ws\""
                    ]
    },
    {
        "name":  "Hancitor",
        "type":  "Loader",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "An email-spread loader that installs other malware.",
        "strings":  [
                        "guid=%i64u&build=%s&info=%s&ext=%s&ip=%s&type=1&win=%d.%d",
                        "rundll32.exe %s, start"
                    ]
    },
    {
        "name":  "SystemBC",
        "type":  "Backdoor",
        "conf":  "possible",
        "need":  2,
        "verified":  true,
        "about":  "A proxy backdoor used to hide attackers' traffic, often in ransomware attacks.",
        "strings":  [
                        "get /tor/rendezvous2/%s http/1.0",
                        "-windowstyle hidden -ep bypass -file \""
                    ]
    },
    {
        "name":  "WarmCookie",
        "type":  "Backdoor",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A backdoor spread through fake job offers that lets attackers look around a PC and run more malware.",
        "strings":  [
                        "\"main invoked.\"",
                        "\"main returned.\"",
                        "error: cannot write file",
                        "ok (no output data)",
                        "ok (see 'files' tab)"
                    ]
    },
    {
        "name":  "Rubeus",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  4,
        "verified":  true,
        "about":  "A tool for abusing Windows Kerberos logins, used by testers and attackers.",
        "strings":  [
                        "658c8b7f-3664-4a95-9572-a3e5871dfc06",
                        "[*] printing argument list for use with rubeus",
                        "[+] ticket successfully imported!",
                        "[+] tickets successfully purged!",
                        "[*] searching for accounts that support aes128_cts_hmac_sha1_96/aes256_cts_hmac_sha1_96",
                        "[*] action: tgt harvesting (with auto-renewal)",
                        "[x] unable to retrieve tgt using tgtdeleg",
                        "[!] unhandled rubeus exception:",
                        "[*] using a tgt /ticket to request service tickets"
                    ]
    },
    {
        "name":  "SharpHound",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A tool that maps Active Directory networks to find paths to admin access.",
        "strings":  [
                        "a517a8de-5834-411d-abda-2d0e1766539c",
                        "90a6822c-4336-433d-923f-f54ce66ba98f",
                        "initializing sharphound at {time} on {date}",
                        "sharphound completed {number} loops! zip file written to {filename}",
                        "[-] removed dcom collection"
                    ]
    },
    {
        "name":  "Certify",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  8,
        "verified":  true,
        "about":  "A tool for finding weaknesses in Windows certificate services.",
        "strings":  [
                        "<displayntauthcertificates>b_",
                        "<printallowpermissions>b_",
                        "<showvulnerabletemplates>b_",
                        "<parsecertificateapplicationpolicies>b_",
                        "<printcerttemplate>b_",
                        "64524ca5-e4d0-41b3-acc3-3bdbefd40c97",
                        "certify.exe find /vulnerable",
                        "certify.exe request /ca"
                    ]
    },
    {
        "name":  "Seatbelt",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A tool that gathers security details about a PC during an attack or test.",
        "strings":  [
                        "aec32155-d589-4150-8fe7-2900df4554c8",
                        "logonid=\"(\\d+)",
                        "domain=\"(.*)\",name=\"(.*)\"",
                        "^\\w*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\w*",
                        "(^https?://.+)|(^ftp://)",
                        "[0-9a-fa-f]{8}[-][0-9a-fa-f]{4}[-][0-9a-fa-f]{4}[-][0-9a-fa-f]{4}[-][0-9a-fa-f]{12}",
                        "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?"
                    ]
    },
    {
        "name":  "GodPotato",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A tool that raises privileges to SYSTEM on Windows.",
        "strings":  [
                        "godpotatocontext was not initialized",
                        "godpotatostoragetrigger",
                        "[*] dcom obj guid: {0}",
                        "[*] dispatchtable: 0x{0:x}",
                        "[*] useprotseqfunction: 0x{0:x}",
                        "[*] process start with pid {0}",
                        "[!] impersonatenamedpipeclient fail error:{0}",
                        "[*] cogetinstancefromistorage: 0x{0:x}",
                        "[*] trigger rpcs"
                    ]
    },
    {
        "name":  "Kerbrute",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A tool for guessing Active Directory logins.",
        "strings":  [
                        "github.com/ropnop/kerbrute/session.kerbrutesession.testusername",
                        "github.com/ropnop/kerbrute/cmd.makesprayworker",
                        "github.com/ropnop/kerbrute/cmd.makeenumworker",
                        "bruteforcecombos",
                        "userenum [flags] <username_wordlist>"
                    ]
    },
    {
        "name":  "SafetyKatz",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "A tool that uses Mimikatz to pull passwords from a memory dump.",
        "strings":  [
                        "8347e81b-89fc-42a9-b22c-f59a6a572dec",
                        "[x] not in high integrity, unable to grab a handle to lsass!",
                        "[x] dump directory \"{0}\" doesn't exist!",
                        "[x] process is not 64-bit, this version of mimikatz won't work yo'!",
                        "[+] dump successful!"
                    ]
    },
    {
        "name":  "WinPEAS",
        "type":  "Attack tool",
        "conf":  "strong",
        "need":  5,
        "verified":  true,
        "about":  "A tool that scans a PC for ways to gain higher privileges.",
        "strings":  [
                        "consolehost_history.txt",
                        "interesting files and registry",
                        "cloud credentials",
                        "accessed:{2} -- size:{3}",
                        "unattend files",
                        "looking for common sam",
                        "found installed wsl distribution",
                        "check skipped, if you want to run it",
                        "cached gpp passwords",
                        "[cc][rr][ee][dd][ee][nn][tt][ii][aa][ll]|[pp][aa][ss][ss][ww][oo]"
                    ]
    },
    {
        "name":  "r77",
        "type":  "Rootkit",
        "conf":  "strong",
        "need":  3,
        "verified":  true,
        "about":  "An open-source rootkit that hides files, processes and registry keys.",
        "strings":  [
                        "service_names",
                        "process_names",
                        "tcp_remote",
                        "reflectivedllmain"
                    ]
    }
]);
})(typeof window !== 'undefined' ? window : globalThis);