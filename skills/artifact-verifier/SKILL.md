---
name: artifact-verifier
description: >-
  Audit files, repositories, releases, manifests, checksums, and ZIP archives for completeness, reproducibility, path safety, secret exposure, generated noise, and truthful readiness labels. Use whenever an artifact is promised, packaged, uploaded, mirrored, or called production-ready. Require concrete bytes, hashes, item counts, semantic checks, and a status boundary. Reject missing, empty, unreadable, traversal-containing, duplicate, case-colliding, symlinked, or hash-drifted artifacts.
---

# Artifact Verifier

1. Freeze the expected scope before inspecting the candidate.
2. Inventory relative paths, sizes, file types, symlinks, duplicates, and case-fold collisions.
3. Run semantic checks appropriate to the artifact, then scan for credentials and generated noise.
4. Build the manifest outside the artifact when possible; verify it after every copy or repack.
5. For ZIP files, test CRC, traversal paths, duplicate members, compression-ratio limits, and round-trip hashes.
6. Report the lifecycle precisely: created, tested-locally, packaged, committed, deployed, invoked, verified-live.
7. Return PASS only with path/link, bytes, SHA-256, file count, commands, and explicit non-claims.

Use `scripts/archive_qc.py` for deterministic ZIP checks. See [references/contract.md](references/contract.md).
