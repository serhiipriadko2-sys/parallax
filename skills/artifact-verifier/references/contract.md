# Artifact verification contract

Fail closed on any of the following:

- missing, extra, empty, unreadable, or hash-mismatched required file;
- absolute path, `..` traversal, duplicate ZIP member, or case-fold collision;
- symlink or device entry in a distributable archive;
- generated noise such as `__pycache__`, `.pyc`, `.pytest_cache`, `.DS_Store`, or `*.egg-info`;
- suspicious compression ratio above the configured limit;
- secret-shaped value not explicitly cleared;
- readiness claim that outruns observed lifecycle evidence.

A checksum proves byte identity, not semantic correctness, safe behavior, deployment, invocation, or effect.
