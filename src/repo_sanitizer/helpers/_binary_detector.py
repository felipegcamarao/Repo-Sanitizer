"""_binary_detector.py — deteccao binario vs texto via magic-bytes (ADR-009 + RS-006/RS-019).

Bloco 02 FULL impl: 14 magic-bytes canonicos cobrindo formatos comuns em repos
(images PNG/JPEG/GIF/WebP/BMP/ICO; documents PDF/Office; archives ZIP/7Z/RAR/GZ;
executables ELF/PE/Mach-O; data SQLite/Class).

Heuristica:
1. Match em magic-bytes conhecidos -> binario (label canonico).
2. OU presenca de byte 0x00 (null-byte) nos primeiros 8 KB -> binario.

Aceita FP raros (ex: arquivos texto com null-byte intencional) per INV-5
Modo Paranoico — preferimos classificar como binario "por seguranca" (F3
deep-scan ainda pode achar string em primeiros 64 KB de binarios; ADR-021).

API publica:
    MAGIC_BYTES: dict[bytes, str]
    DEFAULT_SAMPLE_BYTES: int (8 KB)
    detect_magic(data: bytes) -> str | None
    has_null_byte(data: bytes) -> bool
    is_binary(path: Path, sample_bytes=8192) -> bool
    classify(path: Path, sample_bytes=8192) -> dict[str, str | bool | int]
    sample_file(path: Path, n: int) -> bytes  # helper read defensivo

Uso F1 (Bloco 02): _binary_detector.classify(path) -> {is_binary, magic_label, ...}
e o resultado vai para FilterDiffEntry.is_binary (FILTER_DIFF.md).
"""
from __future__ import annotations

from pathlib import Path

# Magic-bytes canonicos (formato: prefix_bytes -> label).
# Ordem importa: prefixos mais especificos antes de mais curtos quando ambiguos.
MAGIC_BYTES: dict[bytes, str] = {
    # Images
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF87a": "GIF87",
    b"GIF89a": "GIF89",
    b"BM": "BMP",
    b"\x00\x00\x01\x00": "ICO",
    b"RIFF": "WebP/RIFF",  # WebP/AVI/WAV — RIFF container
    # Documents
    b"%PDF-": "PDF",
    # Archives / Office (ZIP-based: docx, xlsx, jar, etc.)
    b"PK\x03\x04": "ZIP/Office",
    b"PK\x05\x06": "ZIP-empty",
    b"PK\x07\x08": "ZIP-spanned",
    b"7z\xbc\xaf\x27\x1c": "7Z",
    b"Rar!\x1a\x07\x00": "RAR4",
    b"Rar!\x1a\x07\x01\x00": "RAR5",
    b"\x1f\x8b": "GZIP",
    b"BZh": "BZIP2",
    b"\xfd7zXZ\x00": "XZ",
    # Executables
    b"\x7fELF": "ELF",
    b"MZ": "PE/DOS",  # Windows executables (.exe, .dll)
    b"\xfe\xed\xfa\xce": "Mach-O-32",
    b"\xfe\xed\xfa\xcf": "Mach-O-64",
    b"\xcf\xfa\xed\xfe": "Mach-O-64-LE",
    b"\xca\xfe\xba\xbe": "Java/Mach-O-fat",  # JVM .class OR Mach-O fat
    # Data formats
    b"SQLite format 3\x00": "SQLite3",
    b"\x00asm": "WASM",
}

DEFAULT_SAMPLE_BYTES = 8 * 1024  # 8 KB


def sample_file(path: Path, n: int = DEFAULT_SAMPLE_BYTES) -> bytes:
    """Le os primeiros n bytes de path; retorna b'' em erro de IO."""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def detect_magic(data: bytes) -> str | None:
    """Retorna label da magic-byte se data comeca com uma; None caso contrario."""
    for prefix, label in MAGIC_BYTES.items():
        if data.startswith(prefix):
            return label
    return None


def has_null_byte(data: bytes) -> bool:
    """True sse data contem 0x00 (heuristica binario)."""
    return b"\x00" in data


def is_binary(path: Path, sample_bytes: int = DEFAULT_SAMPLE_BYTES) -> bool:
    """Heuristica: magic-byte match OU null-byte presence nos primeiros sample_bytes."""
    sample = sample_file(path, sample_bytes)
    if not sample:
        return False
    if detect_magic(sample) is not None:
        return True
    return has_null_byte(sample)


def classify(path: Path, sample_bytes: int = DEFAULT_SAMPLE_BYTES) -> dict[str, str | bool | int]:
    """Retorna {is_binary, magic_label, has_null_byte, sample_size}."""
    sample = sample_file(path, sample_bytes)
    if not sample:
        return {
            "is_binary": False,
            "magic_label": "",
            "has_null_byte": False,
            "sample_size": 0,
        }
    magic = detect_magic(sample) or ""
    null = has_null_byte(sample)
    return {
        "is_binary": bool(magic) or null,
        "magic_label": magic,
        "has_null_byte": null,
        "sample_size": len(sample),
    }


__all__ = [
    "DEFAULT_SAMPLE_BYTES",
    "MAGIC_BYTES",
    "classify",
    "detect_magic",
    "has_null_byte",
    "is_binary",
    "sample_file",
]
