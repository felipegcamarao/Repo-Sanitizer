"""helpers/ — SSOT cross-cutting do repo-sanitizer-agent.

Inclui copias locais Sentinel (_yaml_codec, _integrity) + helpers proprios
(_fs_writer, _audit, _state_machine, _injection_filter, etc).

NUNCA importar Sentinel upstream em runtime (ADR-022/023 + DEF-08).
"""
from __future__ import annotations
