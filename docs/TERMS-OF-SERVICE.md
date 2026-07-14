# AegisGate Lens — Terms of Service

**Last updated:** 2026-07-09
**Effective for:** AegisGate Lens v0.1.4
**Licensor:** AegisGate Security, LLC ("AegisGate", "we", "us")
**Licensee:** End user of the AegisGate Lens Chrome extension ("you", "your")

These Terms of Service ("ToS") govern your use of the
AegisGate Lens Chrome browser extension. By installing or
using the Lens, you agree to these ToS.

AegisGate Lens is **open-source software** licensed under
the Apache License 2.0 (`LICENSE` in the repository). The
Apache 2.0 license governs your rights to copy, modify,
and redistribute the source code. **These ToS are
separate from the Apache 2.0 license** and govern your
**use** of the installed extension, not your rights to the
source code.

## 1. Eligibility

You must be at least 13 years old (or the minimum age
required by your jurisdiction) to install AegisGate Lens.
The Lens is not directed to children under 13 and we do
not knowingly collect any data from children under 13.

If you are entering into these ToS on behalf of a company
or organization, you represent that you have the
authority to bind that entity to these ToS.

## 2. License grant

Subject to your compliance with these ToS and the Apache
2.0 license terms, AegisGate Security, LLC grants you a
non-exclusive, non-transferable, non-sublicensable,
revocable license to:

1. Install and use the AegisGate Lens Chrome extension
   in your web browser(s), on devices you own or control.
2. Use the Lens for personal or commercial purposes,
   subject to Section 5 (Acceptable Use).
3. Use the Lens in conjunction with any of the supported
   AI chat tools (chatgpt.com, claude.ai, gemini.google.com,
   copilot.microsoft.com, perplexity.ai, duck.ai,
   grok.com, chat.mistral.ai).

The Lens is provided **free of charge**. There is no
"Pro", "Teams", "Business", or "Enterprise" tier of the
Lens itself. The AegisGate Platform is a separate paid
product with separate terms (`aegisgatesecurity.io/platform/terms`).

## 3. License restrictions

You may not:

1. **Reverse-engineer** the Lens for the purpose of
   creating a competing product, except to the extent
   that this restriction is prohibited by applicable law
   (e.g., for interoperability under EU Directive 2009/24).
2. **Resell** the Lens by itself, or bundle it with
   another product for the purpose of reselling. The
   Apache 2.0 license § 2 (which states the Lens is
   provided "AS IS") controls for any redistribution; the
   restrictions in this Section 3 are additive for use,
   not for redistribution.
3. **Interfere with** the Lens's operation, including
   (but not limited to) bypassing, disabling, or
   circumventing any feature (e.g., the dismiss button,
   the opt-in prompt, the privacy banner).
4. **Use the Lens in connection with** any activity that
   violates applicable law (e.g., GDPR, HIPAA, CCPA,
   EU AI Act, GLBA, COPPA, or any other law applicable
   to you).

## 4. Privacy and data collection

**AegisGate Lens does not collect any user data by
default.** The Lens is 100% on-device. The detection
runs in your browser, against the prompts you type, and
the results are displayed in a banner. The Lens makes no
network requests, sends no telemetry, and does not log
any prompt content.

**Opt-in telemetry.** The Lens includes an opt-in path
for sending anonymous, metadata-only false-positive
reports to AegisGate Security's threat-intel backend
(lens.aegisgatesecurity.io). The opt-in is OFF by default.
When enabled, the only data sent is:

- **Hashed domain** (16 hex chars, rotated periodically).
  The destination domain (e.g., `chatgpt.com`) is hashed
  with a salt that is NOT in the extension bundle; the
  AegisGate backend cannot recover the original domain
  without brute-forcing the hash.
- **Category** (e.g., `pii_ssn`, `secret_aws_key`).
  Not the value; only the category.
- **Severity** (e.g., `critical`, `high`, `medium`).
- **Action** (e.g., `cancel`, `redact`, `send`,
  `false-positive`).

No prompt content. No URLs. No page content. No user
identifiers. No cookies. No localStorage abuse.

The opt-in is per-dismissal. You must click "Submit &
dismiss" on a specific banner for a specific false-
positive report to be sent. There is no global opt-in
toggle.

For the full privacy policy, see `docs/PRIVACY-POLICY.md`
or visit `aegisgatesecurity.io/lens/privacy`.

## 5. Acceptable Use

You may use the Lens for any lawful purpose, including
commercial purposes. The following are **not acceptable
uses** and are grounds for termination of your license
under Section 7:

1. **Reverse-engineering** the Lens for the purpose of
   creating a product that competes with the AegisGate
   Platform (i.e., a server-side prompt-content filter).
2. **Distributing modified versions** of the Lens with
   the AegisGate name, brand, or trademarks attached.
3. **Bypassing the privacy** of the Lens (e.g., by
   injecting a content script that exfiltrates the
   detection results to a third-party server).
4. **Using the Lens to facilitate** any illegal activity,
   including (but not limited to) fraud, identity theft,
   unauthorized access to computer systems, or the
   distribution of malicious code.

## 6. Intellectual property

The Lens is open-source software licensed under Apache
2.0. The Lens name, the AegisGate name, the AegisGate
logo, the AegisGate Lens shield icon, and the AegisGate
brand are trademarks of AegisGate Security, LLC.

You may use the Lens under the Apache 2.0 license (which
permits commercial use, modification, and redistribution)
but you may NOT use the AegisGate name, logo, or trademarks
in a way that suggests endorsement by AegisGate without
our written permission.

## 7. Termination

These ToS are effective until terminated. You may
terminate at any time by uninstalling the Lens from your
browser. We may terminate your license if:

1. You materially breach these ToS and fail to cure the
   breach within 30 days of written notice.
2. We discontinue the Lens (we will provide at least
   90 days' notice via the GitHub release notes).
3. Google removes the Lens from the Chrome Web Store
   (we will provide a self-installable artifact on the
   GitHub Releases page in this case).

Upon termination, you must uninstall the Lens. Sections
4 (Privacy), 8 (Disclaimers), 9 (Limitation of Liability),
10 (Indemnification), and 12 (Governing Law) survive
termination.

## 8. Disclaimers

THE LENS IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT
WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
(WITHOUT LIMITATION) THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
NONINFRINGEMENT.

**THE LENS IS A WARNING TOOL, NOT A CONTENT FILTER.** The
Lens displays a banner when it detects content matching
one of its 132 patterns. The Lens does NOT block the
user from sending the prompt. The user can always press
"Send Anyway" and the prompt will be sent to the AI
provider. The Lens does NOT guarantee detection of all
PII, all secrets, all XSS, or all compliance-relevant
language. The Lens's detection rate is approximately
98.99% on the in-target held-out set; the false
positive rate is approximately 7.40% on real user
prompts; the adversarial robustness (paraphrasing,
base64, OCR, etc.) is partial and is documented in
`docs/THREAT-MODEL-v0.1.0-BETA.md` F-15 and F-20.

**The Lens does NOT provide legal, compliance, or
security guarantees.** The Lens is a tool that helps
users be aware of potentially sensitive content in their
prompts. It does not replace your organization's
security, compliance, or legal processes. If you need
guaranteed detection, server-side enforcement, or audit
logging, you need the AegisGate Platform (a separate
paid product), not the Lens.

## 9. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO
EVENT SHALL AEGISGATE SECURITY, LLC, ITS AFFILIATES,
OFFICERS, DIRECTORS, EMPLOYEES, AGENTS, OR LICENSORS BE
LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF
PROFITS OR REVENUE, WHETHER INCURRED DIRECTLY OR
INDIRECTLY, OR ANY LOSS OF DATA, USE, GOODWILL, OR
OTHER INTANGIBLE LOSSES, RESULTING FROM:

1. YOUR USE OF (OR INABILITY TO USE) THE LENS.
2. ANY CONDUCT OR CONTENT OF ANY THIRD PARTY ON OR
   THROUGH THE LENS (e.g., the AI provider's content).
3. ANY UNAUTHORIZED ACCESS, USE, OR ALTERATION OF YOUR
   PROMPTS OR DETECTION RESULTS.

IN NO EVENT SHALL AEGISGATE'S TOTAL LIABILITY FOR ALL
CLAIMS RELATING TO THE LENS EXCEED ONE HUNDRED U.S.
DOLLARS ($100.00) OR THE EQUIVALENT IN YOUR LOCAL
CURRENCY.

SOME JURISDICTIONS DO NOT ALLOW THE LIMITATION OF
INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THE ABOVE
LIMITATIONS MAY NOT APPLY TO YOU.

## 10. Indemnification

You agree to indemnify, defend, and hold harmless
AegisGate Security, LLC and its affiliates, officers,
directors, employees, agents, and licensors from and
against any and all claims, damages, obligations, losses,
liabilities, costs, or expenses (including reasonable
attorneys' fees) arising from:

1. Your use of the Lens in violation of these ToS.
2. Your violation of any third-party right, including
   any copyright, trademark, or privacy right.
3. Any claim that your use of the Lens has caused damage
   to a third party.

## 11. Updates and changes to these ToS

We may update these ToS from time to time. We will
announce material changes via the GitHub release notes.
Continued use of the Lens after a material change
constitutes acceptance of the new ToS.

The current ToS is always available at
`docs/TERMS-OF-SERVICE.md` in the Lens repository and at
`aegisgatesecurity.io/lens/terms`.

## 12. Governing law and dispute resolution

These ToS are governed by the laws of the State of
Delaware, USA, without regard to its conflict-of-laws
principles.

Any dispute arising out of or relating to these ToS
shall be resolved exclusively in the state and federal
courts located in Wilmington, Delaware, USA. You
consent to the personal jurisdiction of these courts.

If you are a consumer in the European Union, you retain
the protection of the mandatory provisions of the law
of your country of residence, and you may bring
proceedings in the courts of your country of residence.

If you are a consumer in California, USA, the mandatory
provisions of California consumer protection law apply.

## 13. Severability

If any provision of these ToS is held to be invalid or
unenforceable, that provision shall be enforced to the
maximum extent permissible, and the remaining provisions
shall remain in full force and effect.

## 14. Entire agreement

These ToS, together with the Apache 2.0 LICENSE, the
`docs/PRIVACY-POLICY.md`, and the `docs/THREAT-MODEL-v0.1.0-BETA.md`,
constitute the entire agreement between you and
AegisGate Security, LLC with respect to your use of the
Lens.

## 15. Contact

If you have questions about these ToS, contact:

- **Email:** legal@aegisgatesecurity.io
- **Postal:** AegisGate Security, LLC, 8 The Green,
  Suite #5198, Dover, DE 19901, USA
- **PGP key:** `aegisgatesecurity.io/.well-known/pgp-key.asc`

---

**Signed-off-by:** AegisGate Security <legal@aegisgatesecurity.io>
**Last updated:** 2026-07-09
**Effective for:** AegisGate Lens v0.1.4
**License of this document:** CC-BY-4.0 (you may copy, modify,
and redistribute)