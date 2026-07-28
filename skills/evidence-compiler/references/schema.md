# Claim graph schema

```json
{
  "as_of": "2026-07-28T00:00:00Z",
  "claims": [
    {
      "id": "F1",
      "type": "FACT",
      "status": "VERIFIED",
      "confidence": 0.9,
      "evidence": [
        {
          "ref": "source-id",
          "source_class": "primary",
          "observed_at": "2026-07-28T00:00:00Z",
          "valid_until": null,
          "content_hash": null
        }
      ],
      "dependencies": [],
      "falsifier": "A newer authoritative source contradicts the claim"
    }
  ]
}
```

Derived confidence must not exceed the minimum confidence of verified dependencies. Repeated claims wrapping the same evidence do not create independent support.
