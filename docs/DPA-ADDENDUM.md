# AegisGate Lens — Data Processing Addendum (DPA)

**Last updated:** 2026-07-09
**Effective for:** AegisGate Lens v0.1.0-beta
**Data processor:** AegisGate Security, LLC ("AegisGate")
**Data controller:** The end user / customer (you)

This Data Processing Addendum ("DPA") supplements the
AegisGate Lens Terms of Service (`docs/TERMS-OF-SERVICE.md`)
and applies to the extent that AegisGate processes any
personal data on your behalf in connection with the Lens.

## 1. The 1-paragraph summary

**AegisGate Lens does not process your personal data.
The Lens runs 100% in your browser. The only data that
ever crosses a network wire is opt-in, metadata-only,
anonymized, domain-hashed telemetry (which the Lens
describes as "I detected X category Y on Z hashed
domain"). The Lens does not see your prompt content,
your AI provider's content, or any other personal data
that would require a GDPR Article 28 Data Processing
Agreement.**

If you are a GDPR data controller and you need a formal
DPA for compliance reasons, this document is the DPA.
The remainder of this document explains what (little)
data the Lens actually processes, and why even this
small amount does not require a full Article 28 contract.

## 2. Definitions

For the purposes of this DPA:

- **"Personal data"** has the meaning given in Article
  4(1) of Regulation (EU) 2016/679 ("GDPR"). It includes
  any information relating to an identified or
  identifiable natural person.
- **"Processing"** has the meaning given in Article 4(2)
  of the GDPR. It includes any operation performed on
  personal data, including collection, storage, retrieval,
  consultation, use, disclosure, and erasure.
- **"Data subject"** means the identified or
  identifiable natural person to whom personal data
  relates.
- **"Data controller"** means the natural or legal
  person which, alone or jointly with others, determines
  the purposes and means of the processing of personal
  data.
- **"Data processor"** means a natural or legal person
  which processes personal data on behalf of the
  controller.

## 3. Roles of the parties

You (the end user or your organization) are the **Data
Controller** for any personal data you input into the AI
chat tools protected by AegisGate Lens. AegisGate
Security, LLC is the **Data Processor** only to the
limited extent described in Section 4.

## 4. What data AegisGate processes (and why this DPA is essentially a no-op)

AegisGate processes the following categories of data in
connection with the Lens:

### 4.1 The opt-in telemetry signal (opt-in only)

When you click "Submit & dismiss" on a banner that you
believe to be a false positive, the Lens sends one
metadata-only signal to the AegisGate backend at
`lens.aegisgatesecurity.io/api/v1/fp-reports`. The signal
contains:

- **Hashed domain** (16 hex chars, e.g.,
  `a3f1c8d2b9e07456`).
  This is a one-way SHA-256 prefix of the AI provider's
  domain (e.g., `chatgpt.com`), computed with a salt
  that is NOT in the extension bundle. AegisGate
  cannot recover the original domain from the hash
  without brute-forcing the 64-bit hash space.
- **Category** (e.g., `pii_ssn`, `secret_aws_key`).
- **Severity** (e.g., `critical`, `high`, `medium`).
- **Action** (`submit` for the opt-in path).
- **False-positive reason** (e.g., `test_data`,
  `own_data`, `legitimate_use_case`).

This data is NOT personal data under GDPR Article 4(1).
It does not identify a natural person. It identifies a
**detection event** on a **hashed AI provider domain**.
No data subject can be identified from this data.

The hashed domain is the AI provider's domain (e.g.,
`chatgpt.com`), not the user's domain or any user
identifier. The category is the regex pattern name
(e.g., `pii_ssn`), not the value (the value is never
sent). The severity is a hand-assigned enum, not user
data. The action is one of three strings, not user data.
The reason is one of three strings, not user data.

**Lawful basis (GDPR Article 6):** explicit consent
(Article 6(1)(a)). The user clicks "Submit & dismiss"
on a specific banner, which constitutes a clear
affirmative action. The opt-in is per-dismissal; the
user can dismiss without submitting (the "Just dismiss
(private)" option).

### 4.2 What AegisGate does NOT process

To be explicit, AegisGate does NOT process:

- **Prompt content.** The Lens's content script makes
  no `fetch()` calls. The Lens's service worker makes
  no `fetch()` calls on the content script's behalf.
  Verified by code review of `src/content.js`,
  `src/background.js`, and `src/util/prompt-detect.js`.
- **URLs, page content, or browser history.** The Lens
  has no access to these in normal operation; the
  content script's only outbound message is the
  detection result.
- **Cookies or localStorage abuse.** The Lens uses
  `chrome.storage.session` (auto-cleared on browser
  restart) for the dismiss flag, with a 24h TTL. No
  cookies are set.
- **User identifiers.** No username, no email, no IP
  address, no device fingerprint, no session ID. The
  Lens is anonymous by design.
- **Behavioral data.** The Lens does not track
  which banners the user sees, which buttons they
  press, how long they think before pressing, etc. The
  only action that produces a network egress is the
  explicit opt-in click on a specific banner.

## 5. Sub-processors

AegisGate does not use any sub-processors for the Lens.
The opt-in telemetry endpoint (`lens.aegisgatesecurity.io`)
is operated by AegisGate Security, LLC directly, on
infrastructure we own and operate. We do not use
third-party analytics services, third-party error
tracking, or any other third-party processor.

## 6. International data transfers

The opt-in telemetry signal is sent to
`lens.aegisgatesecurity.io`, which is hosted in the
United States. If you are a data subject in the European
Union, your data may be transferred to the United States
in connection with the opt-in telemetry.

The hashed-domain mechanism means the data transferred
is not personal data. There is no GDPR-relevant transfer
because there is no personal data being processed.

If you are a data subject in the European Union and you
have concerns about US government access to data, please
note: the hashed domain cannot be reversed without
brute-forcing the hash space; the data is not personal
data; and AegisGate has not received any US government
data requests for the Lens. AegisGate's policy on
government data requests is at
`aegisgatesecurity.io/legal/transparency`.

## 7. Data subject rights

GDPR grants data subjects the following rights:
- Right of access (Article 15)
- Right to rectification (Article 16)
- Right to erasure (Article 17)
- Right to restriction of processing (Article 18)
- Right to data portability (Article 20)
- Right to object (Article 21)

Since AegisGate does not process personal data in
connection with the Lens, these rights do not apply to
the Lens specifically. If you are a data subject in the
European Union and you have a request, contact
privacy@aegisgatesecurity.io. We will respond within
30 days.

## 8. Data retention

AegisGate retains opt-in telemetry signals for a
rolling 12-month window for the purpose of training
the AegisGate Platform's threat-intel layer. After 12
months, the data is anonymized (the hashed domain is
additionally truncated to 8 hex chars) and used only
in aggregate statistics.

You may request that AegisGate delete your specific
telemetry signal at any time by contacting
privacy@aegisgatesecurity.io with the hashed domain
(not the original domain). We will delete within 30 days.

## 9. Security measures

AegisGate implements the following technical and
organizational measures to protect the opt-in
telemetry data:

- **Encryption in transit:** TLS 1.3 for all
  client-server communication.
- **Encryption at rest:** AES-256 on the storage
  layer.
- **Access control:** least-privilege access to the
  telemetry database; no employee has read access
  without a written justification.
- **Audit logging:** every read of the telemetry
  database is logged to an immutable audit log.
- **Incident response:** AegisGate maintains a 24-hour
  breach notification SLA for any data incident.

For the full security posture, see
the published public summary at `docs/THREAT-MODEL.md`.

## 10. Sub-processing, change of controller, etc.

This DPA is in effect for the duration of your use of
the Lens. If AegisGate materially changes the data
processing (e.g., by adding a sub-processor, by
processing new categories of data, or by transferring
the data to a new jurisdiction), we will update this DPA
and notify you via the GitHub release notes at least
30 days before the change takes effect.

If AegisGate undergoes a change of control (e.g., a
merger or acquisition), the new entity will be bound by
the terms of this DPA.

## 11. Governing law

This DPA is governed by the laws of the State of
Delaware, USA, without regard to its conflict-of-laws
principles. The same governing-law provision in the
Terms of Service (`docs/TERMS-OF-SERVICE.md` Section 12)
applies.

If you are a data subject in the European Union, you
retain the protection of the mandatory provisions of
the law of your country of residence, in particular
the GDPR.

## 12. Contact

If you have questions about this DPA, contact:

- **Email:** privacy@aegisgatesecurity.io
- **Postal:** AegisGate Security, LLC, 8 The Green,
  Suite #5198, Dover, DE 19901, USA
- **PGP key:** `aegisgatesecurity.io/.well-known/pgp-key.asc`

---

**Signed-off-by:** AegisGate Security <privacy@aegisgatesecurity.io>
**Last updated:** 2026-07-09
**Effective for:** AegisGate Lens v0.1.0-beta
**License of this document:** CC-BY-4.0
