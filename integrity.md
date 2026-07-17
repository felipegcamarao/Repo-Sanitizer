---
last_setup: 2026-05-26T06:24:08+00:00
schema_version: 4.1.0
agent: repo-sanitizer-agent
---

# Hashes de Integridade

> Gate pre-commit: `python scripts/verify_integrity_manifest.py` exit 0 == OK.
> Mismatch = exit 3 (ADR-015 + ADR-022 + ADR-023).

- file: tests/fixtures/sentinel/_sanitize.py
  sha256: df98455c111eaf8e06aaa728d759f7ae02fe39dabf484145fde3c93adaf0bdd3
  recorded_at: 2026-05-26T06:24:08+00:00
- file: tests/fixtures/sentinel/injection_patterns.json
  sha256: efda33c8956ece57f6689117f7cabccd2443ced7c2302b3b261db535daf7d04a
  recorded_at: 2026-05-26T06:24:08+00:00
- file: src/repo_sanitizer/helpers/_yaml_codec.py
  sha256: 75f6e9466e6002f91a6c4be65f5623eacc61e62190b0af8bcbc3404fdbabc9d6
  recorded_at: 2026-05-26T06:24:08+00:00
- file: src/repo_sanitizer/helpers/_integrity.py
  sha256: d137ce418774635b46a716f0fd77b2882c9b3032acc233418129c63b00a4c7c5
  recorded_at: 2026-05-26T06:24:08+00:00
- file: src/repo_sanitizer/secret_patterns.py
  sha256: 695f6c27c69c37f8df88d6a10cd362eac0be8f06f3a624b78f63dc791754bba5
  recorded_at: 2026-07-12T00:00:00+00:00
