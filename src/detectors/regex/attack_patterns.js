// AegisGate Lens — detectors/regex/attack_patterns.js
// Attack pattern detection: SQL injection, malware, evasion, data exfiltration,
// insider threat, and social engineering request detection.
//
// Ported from Platform v4.7.0 Phase 2 expansion (65 patterns).
// These detect natural-language requests for malicious actions in AI prompts.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    // --- SQL Injection ---
    sqli_payload_request: { severity: 'critical', re: /\b(?:sql\s*injection\s*(?:payload|attack|query|exploit|vector)|injection\s*payload.{0,30}bypass(?:es)?\s*(?:waf|filter|firewall)|sqli\s*payload)\b/gi },
    sqli_waf_bypass: { severity: 'high', re: /\b(?:bypass(?:es)?\s*(?:waf|web\s*application\s*firewall|filter|detection)|waf\s*bypass|filter\s*evasion.{0,30}sql)\b/gi },
    sqli_drop_table: { severity: 'critical', re: /\b(?:drop\s+(?:all\s+)?tables?\s+(?:in|from)\s+(?:the\s+)?(?:production|prod|database|db)|drop\s+database|truncate\s+(?:all|every)\s+tables?|delete\s+from\s+\*\s*|delete\s+from\s+(?:all|every)\s+tables?)\b/gi },
    sqli_data_extraction: { severity: 'critical', re: /\b(?:extract.{0,30}(?:credit\s*card|ssn|password|credential|personal|sensitive|private).{0,30}(?:from\s+)?(?:the\s+)?(?:database|db|table)|dump\s+(?:the\s+)?(?:database|db|table|users?|passwords)|exfiltrat\w*\s+data.{0,30}(?:database|sql|table))\b/gi },
    sqli_union_select: { severity: 'high', re: /(?:['";]?)\s*union\s+(?:all\s+)?select\b.{0,100}(?:information_schema|from\s+users|--|#|\/\*\*\/|null|concat|@@version|version\(\)|database\(\)|sleep\()|\b(?:select|insert|update|delete|drop|alter|create)\b.{0,50}\bfrom\b.{0,100}\b(?:information_schema|mysql\.|pg_|sys\.|master\.)\b/gi },
    sqli_boolean_based: { severity: 'high', re: /\b(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|and\s+'1'\s*=\s*'1'|or\s+true|and\s+false)\b/gi },
    sqli_time_based: { severity: 'high', re: /\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay\s+['"]|benchmark\s*\(|pg_sleep\s*\()\b/gi },
    sqli_stacked_queries: { severity: 'high', re: /;\s*(?:drop|delete|update|insert|alter|create|truncate)\s+/gi },
    sqli_comment_evasion: { severity: 'medium', re: /(?:--|\/\*|\#).{0,20}(?:drop|delete|select|insert|update|union|exec)/gi },
    sqli_generic_request: { severity: 'high', re: /\b(?:generate|write|create|build|construct)\s+(?:a\s+)?sql\s*(?:query|statement|injection).{0,50}(?:extract|steal|dump|bypass|drop|delete|attack|exploit)/gi },
    sqli_union_select_tuned: { severity: 'high', re: /\bunion\s+(?:all\s+)?select\b.{0,80}(?:from\s+users|information_schema|@@version|sleep\(|concat\(|null,\s*null)/gi },

    // --- XSS Request ---
    xss_payload_request: { severity: 'critical', re: /\b(?:cross.?site.?scripting|xss)\s*payload\b|\b(?:generate|create|write|build)\s+(?:a\s+)?(?:xss|cross.?site.?scripting)\s*payload\b/gi },
    xss_exploit_request: { severity: 'critical', re: /\b(?:write|create|generate|build|make)\s+(?:an?\s+)?(?:XSS|cross-?site-?scripting)\s+(?:exploit|attack|vector|injection)\b/gi },
    xss_dom_based: { severity: 'high', re: /\b(?:DOM-?based\s+XSS|DOM\s+XSS|DOM\s+clobbering)\b/gi },
    xss_innerhtml: { severity: 'high', re: /\b(?:innerHTML\s+(?:manipulation|injection|exploit)|XSS\s+(?:vector|payload).{0,20}innerHTML)\b/gi },
    xss_stored_reflected: { severity: 'high', re: /\b(?:stored|reflected|blind)\s+XSS\s+(?:payload|exploit|attack|injection)\b/gi },
    xss_csp_bypass: { severity: 'high', re: /\b(?:XSS|cross-?site-?scripting)\s+payload.{0,30}(?:bypass|evade|circumvent)\s+CSP\b/gi },

    // --- Malware ---
    malware_reverse_shell: { severity: 'critical', re: /\b(?:(?:generate|create|write|build|make)\s+(?:a\s+)?(?:code\s+that\s+creates\s+a\s+)?reverse\s*shell|(?:bash|sh)\s+-i\s+(?:>|&gt;|>&)\s*\/?dev\/(?:tcp|udp)\/\d+\.\d+\.\d+\.\d+\/\d+|nc\s+-e\s+.{0,30}\/bin\/(?:bash|sh)|python\s+-c.{0,50}socket.{0,50}connect|mkfifo\s+.{0,30}\|.{0,10}sh)\b/gi },
    malware_payload_download: { severity: 'critical', re: /\b(?:download(?:s)?\s+(?:and\s+)?execut(?:e|es|ion)|payload\s+(?:download|execut|deploy)|(?:curl|wget|invoke-webrequest|iwr)\s+.{0,50}(?:\|\s*(?:sh|bash|python|perl|exec|eval)|;\s*(?:sh|bash)|&&\s*(?:chmod|sh|bash|\.\/))|(?:download|fetch).{0,30}(?:from|http|evil|attacker|c2).{0,30}execut)\b/gi },
    malware_ransomware: { severity: 'critical', re: /\b(?:(?:write|create|generate|build|make)\s+(?:a\s+)?(?:ransomware|cryptolocker)|ransomware\s+that\s+encrypts|encrypt\s+(?:files?|all\s+files|directory|directories|disk|drive).{0,50}(?:demand|bitcoin|payment|ransom|decrypt)|ransom\s*(?:note|demand|payment)|decrypt(?:ion)?\s*key\s*(?:for|after|once)\s*(?:payment|bitcoin))\b/gi },
    malware_backdoor: { severity: 'critical', re: /\b(?:backdoor\b.{0,60}(?:persisten|evade|bypass|hidden|stealth|undetect)|persisten(?:t|ce).{0,50}(?:backdoor|implant|trojan|rootkit|agent)|create\s+(?:a\s+)?(?:persistent\s+)?backdoor)\b/gi },
    malware_botnet_c2: { severity: 'critical', re: /\b(?:botnet\s*(?:command|control|c2|server|infrastructure)|c2\s*server\b.{0,50}(?:botnet|implant|beacon|agent|payload)|command\s*and\s*control\s*server)\b/gi },
    malware_generic_request: { severity: 'critical', re: /\b(?:write|create|generate|build|develop|make)\s+(?:a\s+)?(?:\w+\s+)?(?:\w+\s+)?(?:malware|virus|trojan|worm|rootkit|keylogger|spyware|rat|bootkit|botnet|implant|dropper|stealer|payload|cryptolocker|lolbin)\b/gi },
    malware_av_evasion: { severity: 'high', re: /\b(?:evade(?:s)?\s*(?:antivirus|anti-?virus|av|detection|edr|xdr|defender|windows\s+defender)|bypass\s*(?:antivirus|anti-?virus|av|edr|xdr|amsi|defender|applocker|gatekeeper|uac)|disable\s*(?:amsi|defender|sysmon|antivirus|edr|security\s+center|applocker|gatekeeper)|undetect(?:able|ed)\s*(?:malware|payload|executable|backdoor)|polymorphi(?:c|sm)\s*(?:malware|payload|code|virus)|packer\s*(?:to\s+)?(?:evade|bypass|undetect))\b/gi },
    malware_keylogger: { severity: 'high', re: /\b(?:keylogger|key\s*logger|capture\s+(?:keyboard|keystroke|key\s*press)|log\s+(?:keystrokes|keyboard\s+input|key\s*strokes))\b/gi },
    malware_cred_harvest: { severity: 'high', re: /\b(?:harvest\s+(?:credentials|passwords|tokens|cookies)|steal\s+(?:credentials|passwords|saved\s+passwords|browser\s+(?:cookies|passwords|data|session))|credential\s*(?:harvesting|theft|stealing|stealer)|stealer\s+that\s+targets\s+(?:session|cookies|passwords))\b/gi },
    malware_privesc: { severity: 'high', re: /\b(?:privilege\s*escalat\w*.{0,50}(?:exploit|payload|malware|implant)|local\s*privilege\s*escalation.{0,30}(?:exploit|payload)|kernel\s*(?:exploit|root).{0,30}(?:privesc|escalat))\b/gi },

    // --- Evasion ---
    evasion_log_purge: { severity: 'high', re: /\b(?:purge|clear|delete|wipe|tamper|modify|alter).{0,20}(?:SIEM|audit|security|event|unified|bash\s+history|system).{0,10}(?:logs?|trails?|records?|history)\b/gi },
    evasion_disable_monitor: { severity: 'high', re: /\b(?:disable|turn\s+off|deactivate|stop|kill|terminate).{0,20}(?:Sysmon|AMSI|EDR|XDR|Windows\s+Defender|Windows\s+Security\s+Center|antivirus|anti-?virus|AppLocker|Gatekeeper|monitoring|detection)\b/gi },
    evasion_hide_process: { severity: 'high', re: /\b(?:hide|conceal|mask|camouflage).{0,20}(?:process(?:es)?|from\s+ps|from\s+task\s+manager|from\s+top|running\s+process)\b/gi },
    evasion_lolbin: { severity: 'high', re: /\b(?:live\s+off\s+the\s+land|LOLBin|LOLBins|living-?off-?the-?land)\b/gi },
    evasion_process_hollowing: { severity: 'high', re: /\b(?:process\s+hollowing|process\s+doppelganging|process\s+herpaderping|inject\s+code\s+into\s+(?:legitimate|signed|trusted)\s+process)\b/gi },
    evasion_memory_scan: { severity: 'high', re: /\b(?:evade|bypass|escape).{0,20}(?:memory\s+scanning|memory\s+scanner|memory\s+analysis|YARA|EDR\s+memory|hooking)\b/gi },
    evasion_dll_sideloading: { severity: 'high', re: /\b(?:DLL\s+side-?loading|DLL\s+hijacking|DLL\s+injection|DLL\s+proxying)\b/gi },
    evasion_ads: { severity: 'medium', re: /\b(?:alternate\s+data\s+streams?|ADS\b).{0,30}(?:hide|conceal|store|embed|smuggle)\b/gi },
    evasion_network_evasion: { severity: 'high', re: /\b(?:evade|bypass|circumvent).{0,20}(?:network\s+(?:detection|IDS|IPS|NDR|monitoring)|firewall|proxy\s+detection)\b/gi },
    evasion_rootkit_stealth: { severity: 'high', re: /\b(?:rootkit\b.{0,30}(?:technique|stealth|hide|persist)|use\s+rootkit\s+(?:techniques?|methods?))\b/gi },
    evasion_uac_bypass: { severity: 'high', re: /\b(?:bypass\s+(?:UAC|User\s+Account\s+Control)|UAC\s+bypass)\b/gi },
    evasion_sandbox: { severity: 'medium', re: /\b(?:bypass|evade|escape|detect).{0,20}(?:sandbox|sand-?box|analysis\s+environment|virtual\s+(?:machine|environment)|VM\s+detection)\b/gi },

    // --- Data Exfiltration & Insider Threat ---
    exfil_sensitive_file_read: { severity: 'critical', re: /\b(?:read|show|display|output|print|reveal|cat|view|dump|include).{0,30}(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts|sudoers|group|gshadow)|~\/\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|~\/\.aws\/credentials|~\/\.aws\/config|~\/\.git-credentials|~\/\.npmrc|~\/\.pypirc|~\/\.docker\/config|\/proc\/self\/environ)/gi },
    exfil_ssh_key: { severity: 'critical', re: /\b(?:read|show|display|output|print|reveal|include).{0,30}(?:the\s+)?(?:file\s+at\s+)?(?:\/root\/\.ssh\/|~\/\.ssh\/|\/home\/\w+\/\.ssh\/).{0,30}(?:id_rsa|id_ed25519|id_ecdsa|identity|private\s*key)\b/gi },
    exfil_env_var: { severity: 'critical', re: /\b(?:output|show|display|print|reveal|give\s+me|tell\s+me|what\s+is|dump).{0,20}(?:the\s+)?(?:value\s+of\s+)?(?:the\s+)?(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|PASSWORD|DB_PASSWORD|DATABASE_URL|REDIS_URL|JWT_SECRET|ENCRYPTION_KEY|AWS_SECRET|OPENAI_API_KEY)\s+(?:environment\s+variable|env\s+var|in\s+(?:the\s+)?env)|env\s*(?:var|variable)\s+(?:API_KEY|SECRET|TOKEN|PASSWORD)/gi },
    exfil_cloud_creds: { severity: 'critical', re: /\b(?:list|show|read|display|output|dump|reveal|extract|print).{0,20}(?:all\s+)?(?:AWS|Azure|GCP|Google).{0,20}(?:credentials?|keys?|tokens?|secrets?).{0,30}(?:in\s+|from\s+|at\s+)?(?:~\/\.aws\/|~\/\.azure\/|~\/\.config\/gcloud\/|credentials\s+file|config\s+file)/gi },
    exfil_config_secrets: { severity: 'critical', re: /\b(?:dump|read|show|display|output|extract|reveal).{0,30}(?:the\s+)?(?:database\s+connection\s+(?:string|url|dsn)|db\s+connection\s+string|connection\s+string.{0,20}(?:from|in)\s+config|secrets?.{0,20}(?:from|in)\s+(?:config|\.env|yaml|yml|json|properties))\b/gi },
    exfil_external_transfer: { severity: 'critical', re: /\b(?:send|transfer|upload|post|transmit|exfiltrat\w*|pipe|forward).{0,30}(?:data|files?|records?|credentials?|secrets?|keys?|customer\s+data|PII|PHI|source\s+code|database\s+dump).{0,30}(?:to\s+|via\s+)(?:external|outside|attacker|evil|pastebin|webhook|discord|telegram|ftp|s3|bucket|email|slack)\b/gi },
    exfil_bulk_access: { severity: 'high', re: /\b(?:dump|export|extract|download|copy|scrape|bulk\s+(?:export|download|extract|copy)).{0,30}(?:all|every|entire|whole|complete)\s+(?:customer|user|employee|patient|financial|medical|database|table|records?|data)\b/gi },
    exfil_staging: { severity: 'high', re: /\b(?:compress|archive|zip|tar|encrypt|bundle|package).{0,30}(?:all|every|entire|sensitive|confidential|proprietary).{0,30}(?:data|files?|records?|documents?|source\s+code|database).{0,30}(?:for\s+(?:transfer|exfil|upload|sending|download)|before\s+(?:sending|uploading|transferring))\b/gi },
    exfil_out_of_scope: { severity: 'high', re: /\b(?:access|query|retrieve|view|read|export|download|copy|dump|extract).{0,30}(?:production|prod|customer|financial|salary|hr|employee|patient).{0,30}(?:database|data|records?).{0,30}(?:from\s+(?:my\s+)?(?:personal|home|unauthorized|unapproved)\s+(?:device|machine|computer|laptop|phone|usb|drive)|to\s+(?:my\s+)?(?:personal|home|unauthorized)\s+(?:device|machine|computer|laptop|phone|usb|drive)|using\s+(?:my\s+)?(?:personal|unapproved|unauthorized)\s+(?:device|machine|computer|laptop|phone)|on\s+(?:an\s+)?(?:unapproved|unauthorized)\s+(?:device|machine))\b/gi },
    exfil_cred_sharing: { severity: 'critical', re: /\b(?:share|send|email|message|post|paste|leak|give).{0,20}(?:my\s+|the\s+|our\s+)?(?:credentials?|passwords?|api\s+keys?|tokens?|secrets?|access\s+keys?|private\s+keys?|admin\s+password).{0,30}(?:with\s+|to\s+)(?:external|third.?party|outside|unauthorized|unknown|someone|anyone|public|rival|competitor|journalist)\b/gi },
    insider_source_code_theft: { severity: 'critical', re: /\b(?:copy|download|take|steal|extract|mirror).{0,20}(?:the\s+)?(?:source\s+code|codebase|repository|proprietary\s+(?:algorithm|code|models?|IP)).{0,30}(?:to\s+|for\s+|and\s+share\s+with\s+)(?:USB|personal|external|public\s+GitHub|competitor|next\s+job|side\s+business|startup|rival)\b/gi },
    insider_data_leak: { severity: 'critical', re: /\b(?:leak|post|share|send|publish|mirror|upload).{0,20}(?:merger|acquisition|financial|proprietary|confidential|internal|trade\s+secret|penetration\s+test).{0,30}(?:to\s+|with\s+)(?:journalist|public|rival|competitor|external|website|wiki|blog)\b/gi },
    insider_unauthorized_use: { severity: 'critical', re: /\b(?:use|access|export|download|copy).{0,20}(?:company|corporate|employer|internal).{0,20}(?:API\s+key|credentials?|database|customer\s+(?:list|data|contact)).{0,30}(?:for\s+|to\s+)(?:my\s+|a\s+)?(?:side\s+business|startup|personal|own|next\s+job|competitor)\b/gi },
    insider_download_unauth: { severity: 'high', re: /\b(?:download|copy|export|extract|take).{0,20}(?:customer|employee|salary|financial|patient|user).{0,20}(?:list|data|records?|database).{0,30}(?:without\s+(?:authorization|approval|permission)|to\s+(?:work\s+from\s+home|personal|home))\b/gi },
    insider_screenshot_exfil: { severity: 'high', re: /\b(?:screenshot|capture|photograph).{0,20}(?:internal|confidential|proprietary|wiki|dashboard|screen).{0,20}(?:and\s+)?(?:post|share|send|upload|email).{0,20}(?:externally|outside|public|external)\b/gi },

    // --- Social Engineering ---
    socialeng_phishing_gen: { severity: 'critical', re: /\b(?:write|create|generate|draft|build|make)\s+(?:a\s+)?(?:phishing|spear-?phishing)\s+(?:email|message|campaign|template|attack)\b/gi },
    socialeng_vishing_smishing: { severity: 'critical', re: /\b(?:write|create|generate|draft|build|make)\s+(?:a\s+)?(?:vishing|smishing)\s+(?:script|message|attack|text|sms)\b/gi },
    socialeng_bec: { severity: 'critical', re: /\b(?:business\s+email\s+compromise|BEC\b).{0,30}(?:template|attack|script|message)\b/gi },
    socialeng_pretexting: { severity: 'high', re: /\b(?:write|create|generate|build|make)\s+(?:a\s+)?(?:pretexting|pretext)\s+(?:script|scenario|story|attack)\b/gi },
    socialeng_whaling: { severity: 'critical', re: /\b(?:write|create|generate|build|make)\s+(?:a\s+)?whaling\s+(?:email|message|attack|campaign)\b/gi },
    socialeng_baiting: { severity: 'high', re: /\b(?:write|create|generate|build|make)\s+(?:a\s+)?baiting\s+(?:message|attack|USB|campaign)\b/gi },
    socialeng_tailgating: { severity: 'high', re: /\b(?:write|create|generate|build|make)\s+(?:a\s+)?tailgating\s+(?:script|attack|scenario|technique)\b/gi },
    socialeng_impersonation: { severity: 'critical', re: /\b(?:phishing|impersonating|spoofing).{0,30}(?:Microsoft\s+365|IT\s+support|HR|helpdesk|bank|paypal|amazon|google|apple|IRS|tax)\b/gi },
    socialeng_landing_page: { severity: 'critical', re: /\b(?:write|create|generate|build|make)\s+(?:a\s+)?phishing\s+(?:landing\s+page|login\s+page|credential\s+harvest\w*\s+page).{0,30}(?:mimic|clone|impersonate|copy|replicate)\b/gi },
    socialeng_pig_butchering: { severity: 'critical', re: /\b(?:pig\s+butchering|romance\s+scam|investment\s+scam).{0,30}(?:script|attack|campaign|message)\b/gi },
    socialeng_physical_access: { severity: 'high', re: /\b(?:social\s+engineering).{0,30}(?:physical\s+access|building\s+access|badge|entry|bypass\s+security)\b/gi }
  };

  function detect(text) {
    if (typeof text !== 'string') text = '';
    var matches = [];
    var keys = Object.keys(PATTERNS);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = PATTERNS[key];
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        matches.push({
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[0].length > 200 ? m[0].substring(0, 200) + '...' : m[0],
          index: m.index
        });
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    matches.sort(function (a, b) { return a.index - b.index; });
    return matches;
  }

  var module = { detect: detect, patterns: PATTERNS };

  if (typeof self !== 'undefined') self.__lensAttackPatterns = module;
  if (typeof window !== 'undefined') window.__lensAttackPatterns = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensAttackPatterns = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);