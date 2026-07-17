"""_binary_policy.py — Politica binaria 3-tier (data/credencial excluidos).

v1.2.0 / MV-06 / RS-NEW-042 / ADR-036 / mitigacao §5-9 (#02 threat model).

Classifica binarios em 3 tiers (HARDCODED — nunca lidos do repo-fonte,
RS-NEW-035):

- **credential**: chaves/keystores/certs em binario (`.pem`, `.key`, `.pfx`,
  `.p12`, `.pkcs12`, `.jks`, `.keystore`, `.kdbx`, ...) -> **EXCLUIR** por default.
- **data**: bancos/dumps/planilhas que podem conter dados de cliente (LGPD,
  INV-12): `.sqlite`, `.sqlite3`, `.db`, `.csv`, `.tsv`, `.parquet`, `.xlsx`,
  `.xls`, `.pkl`, `.pickle`, `.h5`, `.hdf5`, `.docx`, dumps `.sql`/`.dump`/`.bak`
  -> **EXCLUIR** por default.
- **safe**: binario neutro (imagens, midia, wasm, fontes, icones) -> **MANTER**.
  Imagens/PDF mantidos com FLAG "EXIF/metadados nao inspecionados" no report
  (transparencia, nao remocao — parse EXIF e MV-15, fora de escopo / INV-8).

A classificacao usa **extensao + magic-label** (ex.: `SQLite format 3` ->
`data` mesmo sem extensao). Binario precede entropia (so texto recebe entropia).

INV: este modulo e PURO (sem IO, sem leitura de config) — recebe basename +
magic_label ja computados por `_binary_detector`.
"""
from __future__ import annotations

from typing import Literal

BinaryTier = Literal["safe", "data", "credential"]

# ---------------------------------------------------------------------------
# Tiers HARDCODED (RS-NEW-035). Extensoes em lowercase, com ponto.
# ---------------------------------------------------------------------------

# Tier 1 — DADOS/credenciais sensiveis -> EXCLUIR. Credenciais em binario.
CREDENTIAL_EXTENSIONS: frozenset[str] = frozenset({
    ".pem", ".key", ".pfx", ".p12", ".pkcs12", ".jks", ".keystore",
    ".kdbx", ".keychain", ".asc", ".gpg", ".ppk", ".der", ".crt", ".cer",
    ".env.enc",
})

# Tier 1 — DADOS (bancos/dumps/planilhas) -> EXCLUIR por default (LGPD INV-12).
DATA_EXTENSIONS: frozenset[str] = frozenset({
    ".sqlite", ".sqlite3", ".db", ".db3", ".mdb", ".accdb",
    ".csv", ".tsv", ".parquet", ".feather", ".arrow", ".avro", ".orc",
    ".xlsx", ".xls", ".xlsm", ".ods",
    ".pkl", ".pickle", ".npy", ".npz", ".h5", ".hdf5",
    ".dump", ".sql", ".bak", ".dmp",
    ".docx",  # Office docs podem conter dados/PII embutidos
})

# Tier 2 — IMAGENS/MIDIA neutras -> MANTER com flag EXIF (metadados nao inspecionados).
IMAGE_MEDIA_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    ".heic", ".heif", ".pdf",
    ".mp3", ".mp4", ".wav", ".mov", ".avi", ".mkv", ".flac", ".ogg",
})

# Tier 3 — BINARIO NEUTRO (wasm, icones, fontes, etc.) -> MANTER sem flag.
NEUTRAL_EXTENSIONS: frozenset[str] = frozenset({
    ".wasm", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dll", ".dylib", ".class", ".jar",
})

# Magic-labels (de `_binary_detector.MAGIC_BYTES`) que forcam tier DATA mesmo
# sem extensao reconhecida (defesa-em-camadas anti-spoofing por rename).
_DATA_MAGIC_LABELS: frozenset[str] = frozenset({
    "SQLite3",
})

# Magic-labels que indicam IMAGEM/midia com metadados potencialmente sensiveis
# (EXIF/XMP/geo) -> flag quando extensao ausente/mascarada. `ICO`/`BMP` sao
# NEUTROS (icones/bitmaps sem EXIF tipico) e NAO entram aqui.
_IMAGE_MAGIC_LABELS: frozenset[str] = frozenset({
    "PNG", "JPEG", "GIF87", "GIF89", "WebP/RIFF", "PDF",
})


def _ext_of(basename: str) -> str:
    """Extensao lowercase com ponto (`config.SQLite` -> `.sqlite`). "" se nenhuma.

    Cobre tambem o caso composto `.env.enc` (dois segmentos finais).
    """
    low = basename.lower()
    # Caso composto explicito (ex.: arquivo.env.enc)
    if low.endswith(".env.enc"):
        return ".env.enc"
    idx = low.rfind(".")
    if idx <= 0:  # sem ponto, ou dotfile sem extensao (`.gitignore`)
        return ""
    return low[idx:]


def classify_binary_tier(basename: str, magic_label: str) -> BinaryTier:
    """Classifica um binario em `safe` | `data` | `credential` (HARDCODED).

    Prioridade: credential > data > (magic data) > safe. A decisao usa
    extensao primeiro; magic-label e fallback/reforço (anti-rename-spoofing).

    Args:
        basename: nome do arquivo (com extensao).
        magic_label: rotulo de `_binary_detector.classify` (ex.: "SQLite3",
            "PNG", "" se nenhum).

    Returns:
        BinaryTier. Default conservador para neutros = `safe`.
    """
    ext = _ext_of(basename)

    # 1) Credenciais (sempre excluir) — maior prioridade.
    if ext in CREDENTIAL_EXTENSIONS:
        return "credential"

    # 2) Dados (excluir por default; LGPD).
    if ext in DATA_EXTENSIONS:
        return "data"

    # 3) Magic-label forca DATA (ex.: SQLite renomeado p/ `.bin`).
    if magic_label in _DATA_MAGIC_LABELS:
        return "data"

    # 4) Neutro/imagem -> safe (manter). (Flag EXIF decidida por `is_image_media`.)
    return "safe"


def is_image_media(basename: str, magic_label: str) -> bool:
    """True sse o binario e imagem/midia -> MANTER + flag 'EXIF nao inspecionado'.

    So faz sentido chamar quando `classify_binary_tier(...) == "safe"`. Usa
    extensao OU magic-label (PNG/JPEG/PDF etc.).
    """
    ext = _ext_of(basename)
    if ext in IMAGE_MEDIA_EXTENSIONS:
        return True
    return magic_label in _IMAGE_MAGIC_LABELS


def tier_excludes(tier: BinaryTier) -> bool:
    """True sse o tier deve ser EXCLUIDO do destino (data/credential)."""
    return tier in ("data", "credential")


__all__ = [
    "CREDENTIAL_EXTENSIONS",
    "DATA_EXTENSIONS",
    "IMAGE_MEDIA_EXTENSIONS",
    "NEUTRAL_EXTENSIONS",
    "BinaryTier",
    "classify_binary_tier",
    "is_image_media",
    "tier_excludes",
]
