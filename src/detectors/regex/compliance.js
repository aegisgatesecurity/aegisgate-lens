// AegisGate Lens — detectors/regex/compliance.js
// Facet 4: Compliance framework detection. Keyword/phrase-based.
//
// Per schema.js VALID_CATEGORIES[4], 23 compliance categories across
// OWASP LLM Top 10, MITRE ATLAS, EU AI Act, ANP (GDPR data
// protection), and CU (consumer protection).
//
// v1.0 philosophy: match specific phrases that are clear signals
// (e.g., "credit scoring decision" = EU AI Act high-risk). Avoid
// single keywords (e.g., "race" alone is too broad). Future v1.1
// can use ML to add context-aware detection.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var PATTERNS = {
    // --- OWASP LLM Top 10 ---
    owasp_llm01_prompt_injection: {
      severity: 'critical',
      // Direct prompt injection: "ignore previous", "disregard prior",
      // "forget everything", "new instructions:", "system: you are"
      re: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now/gi
    },
    owasp_llm04_model_dos: {
      severity: 'high',
      // Denial-of-service: flooding, overwhelming, massive inputs
      re: /(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?/gi
    },
    owasp_llm08_excessive_agency: {
      severity: 'high',
      // Excessive agency: asking the AI to use tools with no oversight
      re: /(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)/gi
    },
    owasp_llm09_overreliance: {
      severity: 'medium',
      // Overreliance: asking AI to validate critical decisions
      re: /(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)/gi
    },
    owasp_llm10_model_theft: {
      severity: 'high',
      // Model extraction / theft
      re: /(?:extract|reveal|expose|leak|give\s+me)\s+(?:the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)/gi
    },

    // --- MITRE ATLAS ---
    atlas_poison: {
      severity: 'high',
      // Training data poisoning: fine-tune, retrain, or ingest
      // untrusted data. We allow optional intervening words (model,
      // network, system) between the action and the data source.
      re: /(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)/gi
    },
    atlas_exfiltration: {
      severity: 'high',
      // Data exfiltration via the AI
      re: /(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)/gi
    },
    atlas_jailbreak: {
      severity: 'critical',
      // Jailbreak attempts
      re: /\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)/gi
    },

    // --- EU AI Act ---
    eu_ai_act_high_risk: {
      severity: 'high',
      // High-risk use cases per Annex III
      re: /(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:biometric|facial)\s+(?:identification|recognition|verification)|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system/gi
    },
    eu_ai_act_transparency: {
      severity: 'medium',
      // Transparency obligations (Article 50)
      re: /(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI/gi
    },
    eu_ai_act_human_oversight: {
      severity: 'medium',
      // Human oversight (Article 14)
      re: /(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)/gi
    },
    eu_ai_act_robustness: {
      severity: 'low',
      // Robustness/accuracy (Article 15)
      re: /(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)/gi
    },

    // --- ANP (GDPR data protection) ---
    anp_personal_data: {
      severity: 'medium',
      // Personal data / PII in a GDPR context
      re: /(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing/gi
    },
    anp_special_category: {
      severity: 'high',
      // Article 9 special categories (sensitive data)
      re: /(?:racial|ethnic)\s+(?:origin|discrimination)|(?:religious|political)\s+(?:beliefs?|opinions?|affiliation)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+for\s+(?:identification|profiling)|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)/gi
    },

    // --- CU (Consumer protection) ---
    cu_consumer_rights: {
      severity: 'medium',
      re: /(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)/gi
    },
    cu_minor_protection: {
      severity: 'high',
      re: /(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance/gi
    }
  };

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
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

  if (typeof self !== 'undefined') self.__lensCompliance = module;
  if (typeof window !== 'undefined') window.__lensCompliance = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensCompliance = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
