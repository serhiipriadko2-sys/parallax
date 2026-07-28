# Memory and Consent

Conversation context is temporary. Durable memory is a separate, consent-bearing operation.

A candidate discloses exact content, purpose, sensitivity, retention, target, deletion path, and fingerprint. Consent must come from a trusted issuer, bind to that exact fingerprint, include issue and expiry times, and be one-time use. Any candidate change requires new disclosure and consent.

A write is successful only after connector read-back matches the content hash and a receipt is emitted. Direct Archive writes are forbidden. Secrets, credentials, payment data, medical or intimate data, biometrics, private third-party content, and raw transcripts are not stored in the default profile.
