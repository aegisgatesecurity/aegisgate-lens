// AegisGate Lens — pii-financial.js
//
// Financial PII patterns: cryptocurrency wallet addresses and digital payment service identifiers. 9 patterns covering the top crypto chains (BTC, ETH, BNB, LTC, SOL) and the top US digital payment services (PayPal, Stripe, Venmo, Cash App). These are high-risk for credential theft / financial fraud when pasted into a prompt that then gets sent to a model that retains the conversation.
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        pii_crypto_btc: {
          severity: 'high',
          re: /(?:Bitcoin|BTC|btc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{39,59})\b/gi
        },
        pii_crypto_eth: {
          severity: 'high',
          re: /(?:Ethereum|ETH|eth)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40})\b/gi
        },
        pii_crypto_bnb: {
          severity: 'high',
          re: /(?:Binance|BNB|bnb)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40}|bnb[a-zA-HJ-NP-Z1-9]{39})\b/gi
        },
        pii_crypto_ltc: {
          severity: 'high',
          re: /(?:Litecoin|LTC|ltc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([LM3][a-zA-Z0-9]{26,33})\b/gi
        },
        pii_crypto_sol: {
          severity: 'high',
          re: /(?:Solana|SOL|sol)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([1-9A-HJ-NP-Za-km-z]{32,44})\b/gi
        },
        // Digital payment patterns - based on test expectations,
        pii_digital_paypal: {
          severity: 'medium',
          // PayPal email - requires "email" keyword
          // PayPal ID - P followed by digits
          re: /(?:PayPal|paypal)\s+(?:email|email\s+address|email\s+no\.?|ID)\s*[:=]?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Z]\d{9,})\b/gi
        },
        pii_digital_stripe: {
          severity: 'high',
          // Stripe keys and customer/payment IDs
          re: /(?:Stripe|stripe)\s+(?:api\s*key|secret\s*key|publishable\s*key|customer\s*ID|customer|payment\s*ID|payment)?\s*[:=]?\s*(pk_live_[0-9a-zA-Z]{24,50}|sk_live_[0-9a-zA-Z]{24,50}|pk_test_[0-9a-zA-Z]{24,50}|sk_test_[0-9a-zA-Z]{24,50}|cus_[A-Za-z0-9]{21,}|pi_[A-Za-z0-9]{21,}|pay_[A-Za-z0-9]{21,})\b/gi
        },
        pii_digital_venmo: {
          severity: 'medium',
          // Venmo username - @username or username format
          re: /(?:Venmo|venmo)\s+(?:username|user\s+name|handle)?\s*[:=]?\s*(@[a-zA-Z][a-zA-Z0-9._]{0,29}|[a-zA-Z][a-zA-Z0-9._]{1,30})\b/gi
        },
        pii_digital_cashapp: {
          severity: 'medium',
          re: /(?:Cashapp|cashapp|cash\s*app)\s*(?:username|handle)?\s*[:=]?\s*(\$?[a-zA-Z][a-zA-Z0-9._-]{1,20})\b/gi
        },
        // Residence permit patterns
  };

  if (typeof self !== 'undefined') self.__lensPII_financial = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensPII_financial = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensPII_financial = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
