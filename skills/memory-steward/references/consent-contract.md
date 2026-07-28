# Consent contract

A valid consent grant contains:

- unique consent ID;
- exact candidate fingerprint;
- trusted issuer identity;
- issue and expiry timestamps;
- one-time-use enforcement.

A candidate fingerprint binds content hash, candidate ID, purpose, sensitivity, retention, target, and deletion path. Changing any bound field requires a new disclosure and consent.

Never persist credentials, authentication tokens, payment data, medical or intimate data, biometrics, private third-party content, or raw transcripts in the default profile. Direct Archive writes remain forbidden.
