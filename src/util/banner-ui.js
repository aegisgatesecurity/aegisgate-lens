/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Banner UI Module (v0.2)
   =========================================================================

   The banner UI module provides the visible warning UI when sensitive
   data is detected. It's a port of v0.1's banner code (aegisgate-lens
   Day 1, Phase 1.2) with adjustments for v0.2's severityTint signature
   and the modernized detection schema.

   v0.2 changes from v0.1:
   - severityTint now returns { accent, fg, label } object (same as v0.1)
   - detection schema: severity strings (critical/high/medium/low/info)
   - banner creation is triggered after runDetection() returns hits
   - all buttons (Cancel, Edit, Send anyway) recordAction('cancel'/'edit'/'send_anyway')

   Plain JavaScript, no dependencies.
   The bytes in this file are the bytes that run in the browser.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};
  const log = NS.logger || console;

  // Banner constants (same as v0.1)
  const BANNER_BG = 'rgba(10, 12, 16, 0.92)';
  const BANNER_FONT_FAMILY = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

  /**
   * Severity color tinting. Returns { accent, fg, label } for the
   * banner's left border + badge. Identical to v0.1.
   */
  function severityTint(s) {
    switch (s) {
      case 'critical': return { accent: '#f43f5e', fg: '#ffffff', label: 'CRITICAL' };
      case 'high':     return { accent: '#f59e0b', fg: '#0a0c10', label: 'HIGH' };
      case 'medium':   return { accent: '#38bdf8', fg: '#0a0c10', label: 'MEDIUM' };
      case 'low':      return { accent: '#10b981', fg: '#0a0c10', label: 'LOW' };
      case 'info':     return { accent: '#94a3b8', fg: '#0a0c10', label: 'INFO' };
      default:         return { accent: '#94a3b8', fg: '#0a0c10', label: 'INFO' };
    }
  }

  /**
   * Build a style object for banner buttons. Identical to v0.1.
   */
  function buttonStyle(accent) {
    return {
      background: 'transparent',
      color: accent,
      border: '1px solid ' + accent,
      padding: '5px 12px',
      borderRadius: '0',
      cursor: 'pointer',
      fontSize: '13px',
      fontWeight: '500',
      fontFamily: 'inherit',
      letterSpacing: '0.01em',
      transition: 'background 120ms ease, color 120ms ease',
    };
  }

  /**
   * Human-readable description for a category. Falls back to the
   * raw category if no description is available.
   */
  function describeCategory(category) {
    const map = {
      pii_ssn: 'Social Security Number',
      pii_email: 'Email address',
      pii_phone: 'Phone number',
      pii_credit_card: 'Credit card number',
      pii_ip_address: 'IP address',
      pii_full_name: 'Person\'s name',
      pii_health: 'Health information',
      pii_health_v3: 'Health information',
      secret_jwt: 'JWT (JSON Web Token)',
      secret_bearer_token: 'Bearer token',
      secret_api_key: 'API key',
      secret_aws_access_key: 'AWS access key',
      secret_github_pat: 'GitHub personal access token',
      secret_private_key: 'Private cryptographic key',
      jwt_none: 'JWT with "none" algorithm (security vulnerability)',
      xss_payload: 'Cross-site scripting payload',
      source_code: 'Source code in prompt',
      sqli_or_true: 'SQL injection pattern',
      owasp_sensitive_disclosure: 'OWASP sensitive data disclosure',
      prompt_injection_ml: 'Prompt injection (ML-detected)',
      prompt_injection_ml_long: 'Prompt injection (long-content advisory)',
    };
    return map[category] || category;
  }

  /**
   * Show the warning banner. Idempotent — reuses existing banner if
   * present, otherwise creates a new one.
   * @param {Array<{category: string, severity: string, match: string, name: string}>} detections
   */
  function showBanner(detections) {
    if (!detections || detections.length === 0) return;
    let banner = document.getElementById('__aegisgate_lens_banner__');
    if (banner && document.body.contains(banner)) {
      updateBannerContent(banner, detections);
      return;
    }
    banner = document.createElement('div');
    banner.id = '__aegisgate_lens_banner__';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'polite');
    Object.assign(banner.style, {
      position: 'fixed',
      top: '0', left: '0', right: '0',
      zIndex: '2147483647',
      background: BANNER_BG,
      borderBottom: '1px solid rgba(56, 189, 248, 0.18)',
      borderLeft: '3px solid #38bdf8',  // default; overwritten by severity
      padding: '14px 44px 14px 18px',
      fontFamily: BANNER_FONT_FAMILY,
      fontSize: '14px',
      lineHeight: '1.5',
      color: '#f8fafc',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
      boxShadow: '0 4px 24px rgba(0, 0, 0, 0.45)',
    });
    document.body.appendChild(banner);
    updateBannerContent(banner, detections);
    log.info('[AegisGate Lens] Banner shown: ' + detections.length + ' detection(s)');
  }

  /**
   * Update the banner's content. Replaces children; does not
   * recreate the banner element.
   */
  function updateBannerContent(banner, detections) {
    if (!banner) return;
    while (banner.firstChild) banner.removeChild(banner.firstChild);

    // Resolve a representative severity from the detection set
    // (critical > high > medium > low > info).
    const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    let topSev = (detections[0] && detections[0].severity) || 'info';
    for (let i = 1; i < detections.length; i++) {
      const s = (detections[i] && detections[i].severity) || 'info';
      if ((sevRank[s] || 0) > (sevRank[topSev] || 0)) topSev = s;
    }
    const tint = severityTint(topSev);

    // Apply severity accent to the banner's left border + bottom hairline.
    banner.style.borderLeft = '3px solid ' + tint.accent;
    banner.style.borderBottom = '1px solid ' + tint.accent;

    // Header: AegisGate icon + title + severity badge.
    const header = document.createElement('div');
    Object.assign(header.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      marginBottom: '8px',
      flexWrap: 'wrap',
    });

    // Small AegisGate shield icon
    const icon = document.createElement('img');
    icon.src = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
      ? chrome.runtime.getURL('icons/icon-32.png')
      : 'icons/icon-32.png';
    icon.alt = '';
    icon.width = 20;
    icon.height = 20;
    Object.assign(icon.style, {
      width: '20px',
      height: '20px',
      flexShrink: '0',
      display: 'block',
    });
    header.appendChild(icon);

    // Title text
    const title = document.createElement('span');
    Object.assign(title.style, {
      fontWeight: '600',
      color: '#f8fafc',
      letterSpacing: '-0.01em',
    });
    const count = detections.length;
    const isLongAdvisory = detections.some((d) =>
      d.category === 'prompt_injection_ml_long' ||
      d.category === 'prompt_injection_transformer_long'
    );
    title.textContent = isLongAdvisory
      ? 'AegisGate Lens: This long prompt looks unusual — please confirm before sending.'
      : 'AegisGate Lens: ' + count + ' sensitive item' +
        (count === 1 ? '' : 's') + ' detected in your prompt.';
    header.appendChild(title);

    // Severity badge - terminal-style code
    const badge = document.createElement('span');
    Object.assign(badge.style, {
      fontFamily: 'ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace',
      fontSize: '10px',
      fontWeight: '500',
      letterSpacing: '0.12em',
      padding: '2px 6px',
      border: '1px solid ' + tint.accent,
      color: tint.accent,
      background: 'transparent',
      textTransform: 'uppercase',
    });
    badge.textContent = '[' + tint.label + ']';
    header.appendChild(badge);

    banner.appendChild(header);

    // Detection list
    const list = document.createElement('ul');
    Object.assign(list.style, {
      margin: '0 0 10px 0',
      paddingLeft: '20px',
      color: '#94a3b8',
    });
    for (let i = 0; i < detections.length; i++) {
      const d = detections[i];
      const li = document.createElement('li');
      const masked = (d.match || '').length > 8
        ? (d.match || '').slice(0, 4) + '\u2026' + (d.match || '').slice(-4)
        : (d.match || '');
      let label = describeCategory(d.category) + ' (' + d.severity + ') \u2014 match: "' + masked + '"';
      // v0.3.0+ note: the LI textContent must remain in the
      // v0.1 format (the Platform's test wrapper parses it with a
      // strict regex: /^(.+?) \(([^)]+)\) — match: "(.+)"$/).
      // The ML metadata (d.mlScore, d.mlThreshold, d.facet) is
      // preserved in the detection data structure and exposed via
      // the LI's aria-label / title attributes (for accessibility
      // and debug tools), but NOT in the textContent.
      if (d.mlScore !== undefined || d.facet !== undefined) {
        let ariaExtra = '';
        if (d.mlScore !== undefined) {
          ariaExtra += 'ML score: ' + d.mlScore.toFixed(3) +
                       ', threshold: ' + (d.mlThreshold || 0.05).toFixed(2) + '. ';
        }
        if (d.facet !== undefined) {
          ariaExtra += 'Facet: ' + d.facet + '.';
        }
        li.setAttribute('aria-label', label + ' ' + ariaExtra);
        li.setAttribute('title', label + ' ' + ariaExtra);
      }
      li.textContent = label;
      list.appendChild(li);
    }
    banner.appendChild(list);

    // Actions row
    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', gap: '8px', flexWrap: 'wrap' });

    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = isLongAdvisory ? 'Edit prompt' : 'Cancel';
    Object.assign(cancelBtn.style, buttonStyle('#94a3b8'));
    cancelBtn.addEventListener('click', () => {
      if (NS.util && NS.util.contentScript && NS.util.contentScript.recordAction) {
        NS.util.contentScript.recordAction(isLongAdvisory ? 'edit' : 'cancel');
      }
      hideBanner();
    });
    actions.appendChild(cancelBtn);

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    Object.assign(editBtn.style, buttonStyle('#38bdf8'));
    editBtn.addEventListener('click', () => {
      if (NS.util && NS.util.contentScript && NS.util.contentScript.recordAction) {
        NS.util.contentScript.recordAction('edit');
      }
      hideBanner();
    });
    actions.appendChild(editBtn);

    const sendBtn = document.createElement('button');
    sendBtn.textContent = isLongAdvisory ? 'Confirm send' : 'Send anyway';
    Object.assign(sendBtn.style, buttonStyle(isLongAdvisory ? '#10b981' : '#f43f5e'));
    sendBtn.addEventListener('click', () => {
      if (NS.util && NS.util.contentScript && NS.util.contentScript.recordAction) {
        NS.util.contentScript.recordAction('send_anyway');
      }
      hideBanner();
    });
    actions.appendChild(sendBtn);

    banner.appendChild(actions);

    // Dismiss (×) in the corner
    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = '\u00D7';
    dismissBtn.setAttribute('aria-label', 'Dismiss this warning');
    Object.assign(dismissBtn.style, {
      position: 'absolute', top: '10px', right: '14px',
      background: 'transparent', border: 'none',
      fontSize: '22px', lineHeight: '1', cursor: 'pointer',
      color: '#94a3b8', padding: '0 6px',
      fontFamily: 'inherit',
      transition: 'color 120ms ease',
    });
    dismissBtn.addEventListener('mouseenter', () => { dismissBtn.style.color = '#f8fafc'; });
    dismissBtn.addEventListener('mouseleave', () => { dismissBtn.style.color = '#94a3b8'; });
    dismissBtn.addEventListener('click', () => {
      if (NS.util && NS.util.contentScript && NS.util.contentScript.recordAction) {
        NS.util.contentScript.recordAction('dismiss');
      }
      hideBanner();
    });
    banner.appendChild(dismissBtn);
  }

  /**
   * Hide the banner if it exists.
   */
  function hideBanner() {
    const banner = document.getElementById('__aegisgate_lens_banner__');
    if (banner && banner.parentNode) {
      banner.parentNode.removeChild(banner);
    }
  }

  // Expose functions via namespace
  NS.util = NS.util || {};
  NS.util.bannerUI = {
    severityTint,
    buttonStyle,
    describeCategory,
    showBanner,
    hideBanner,
    updateBannerContent,
    BANNER_BG,
    BANNER_FONT_FAMILY,
  };
})();