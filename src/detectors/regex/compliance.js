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
    },
    // ====================================================================
    // NEW PATTERNS (v0.1.0-beta Compliance expansion, 2026-07-04)
    // Each pattern: keyword + brief context, strict regex for low FP.
    // These cover region-specific privacy regulations and
    // cybersecurity frameworks that the Lens should detect so users
    // can flag content containing references to them.
    // ====================================================================
    nist_csf_reference: {
      // NIST Cybersecurity Framework (CSF) identifiers. CSF uses
      // function.category.subcategory (e.g., ID.AM-1, PR.AC-1).
      // We match the 5 function prefixes (ID, PR, DE, RS, RC) and
      // a few of the most common subcategories.
      severity: 'medium',
      re: /\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b/g
    },
    iso_27001_reference: {
      // ISO/IEC 27001 control references. The format is Annex A
      // control IDs (A.5.1, A.6.1, A.8.2, etc.) or clause
      // references (6.1.2, 8.2.1, 10.1.1). The A.x.y format is
      // the most common.
      severity: 'medium',
      re: /\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b/g
    },
    ccpa_reference: {
      // California Consumer Privacy Act (CCPA). Section numbers
      // (1798.100, 1798.105, etc.) or keywords like "CCPA",
      // "California Consumer Privacy", "right to know", "right to
      // delete", "right to opt out", "sale of personal information".
      severity: 'medium',
      re: /\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b/gi
    },
    lgpd_reference: {
      // Brazilian Lei Geral de Protecao de Dados (LGPD). Article
      // references (Art. 7, Art. 18, Art. 46) or keywords
      // ("LGPD", "Lei Geral de Protecao de Dados", "dados pessoais",
      // "controlador", "operador", "ANPD").
      severity: 'medium',
      re: /\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ãa]o\s+de\s+Dados|Art\.\s*\d+(?:[\s,ºo]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b/gi
    },
    pipeda_reference: {
      // Canadian Personal Information Protection and Electronic
      // Documents Act (PIPEDA). Schedule 1 references or keywords
      // ("PIPEDA", "personal information", "consent", "Principle").
      severity: 'medium',
      re: /\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b/gi
    },
    popia_reference: {
      // South African Protection of Personal Information Act (POPIA).
      // Section references (s. 11, s. 14) or keywords ("POPIA",
      // "Information Regulator", "processing of personal information").
      severity: 'medium',
      re: /\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b/gi
    },
    // ====================================================================
    // TOXICITY REGEX FALLBACK (Facet 5)
    // These are the 2 toxicity categories NOT in the unitary/toxic-bert
    // 6-class output. They fall back to regex detection. Per
    // plans/AEGISGATE-LENS-V01BETA-MODEL-DECISION.md (Section 4.1),
    // toxicity_sexual and toxicity_self_harm require regex patterns.
    // The other 5 toxicity categories (toxicity_hate, toxicity_insult,
    // toxicity_obscene, toxicity_threat, toxicity_violence) are
    // covered by the ML detector (unitary/toxic-bert) in
    // src/detectors/ml/toxicity.py.
    // ====================================================================
    toxicity_sexual: {
      // Sexual content indicators. We match explicit sexual terms
      // (avoiding medical/educational contexts). The pattern is
      // conservative -- we require an explicit qualifier to reduce FPs.
      severity: 'high',
      re: /\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b/gi
    },
    toxicity_self_harm: {
      // Self-harm indicators. We match explicit references to self-harm,
      // suicide, and self-injury. Conservative to avoid FPs on
      // mental health discussion (e.g., "how to help someone with
      // depression" should NOT fire; "I want to kill myself" SHOULD).
      severity: 'critical',
      re: /\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b/gi
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
