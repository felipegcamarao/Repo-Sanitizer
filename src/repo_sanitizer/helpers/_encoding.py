"""_encoding.py — multi-encoding scanner (ADR-021 + RS-008 + DEF-03 heuristica sequencial).

Bloco 03 Passo 03.4 (Camada C4 RS-001): FULL impl. Cobre 5 fixtures encoding-bomb
sequenciais (UTF-8 strict, UTF-8 BOM, UTF-16-LE BOM, UTF-16-BE BOM, Latin-1)
+ UTF-7 best-effort. Modo Paranoico INV-5: aceita FP a custa de zero FN.

INVARIANTE (DEF-03): `errors='replace'` obrigatorio — substitui bytes invalidos
por '\\uFFFD' (caractere de substituicao Unicode). NUNCA usar `errors='ignore'`
porque OCULTA segredos (RS-019).

Por que UTF-7 best-effort:
- UTF-7 e considerado deprecated em Python 3.11+ (RFC 2152), mas ainda
  decodificavel via codec `utf_7` quando explicito. Tipico vetor anti-deteccao:
  AT-21 encoding-bomb escolhe UTF-7 esperando que F3 nao decode-la.
- Estrategia: TENTAR decode UTF-7; se LookupError ou UnicodeDecodeError,
  continuar sem falhar (best-effort).

API publica:
    EncodingLabel = Literal["utf-8", "utf-8-bom", "utf-16-le", "utf-16-be",
                            "latin-1", "utf-7", "binary"]
    detect_bom(data: bytes) -> EncodingLabel | None
    try_decode_sequential(data: bytes) -> list[(encoding, text)]
    classify_encoding(path: Path) -> EncodingLabel  # rotulo canonico unico
    iter_decoded_variants(data: bytes) -> Iterable[(encoding, text)]
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Literal

EncodingLabel = Literal[
    "utf-8",
    "utf-8-bom",
    "utf-16-le",
    "utf-16-be",
    "latin-1",
    "utf-7",
    "binary",
]


# BOMs canonicos (defesa RS-008)
BOMS: dict[bytes, EncodingLabel] = {
    b"\xef\xbb\xbf": "utf-8-bom",
    b"\xff\xfe": "utf-16-le",
    b"\xfe\xff": "utf-16-be",
}

# Ordem sequencial de tentativa (DEF-03 default; nao reordenar sem auditar).
# Latin-1 SEMPRE decodifica qualquer byte (256 chars validos); por isso vai por
# ultimo (catch-all). UTF-7 vem entre Latin-1 e UTF-16 como best-effort.
_SEQUENTIAL_ENCODINGS: tuple[EncodingLabel, ...] = (
    "utf-8",
    "utf-16-le",
    "utf-16-be",
    "utf-7",
    "latin-1",
)


def detect_bom(data: bytes) -> EncodingLabel | None:
    """Detecta BOM. Retorna label ou None."""
    for bom, label in BOMS.items():
        if data.startswith(bom):
            return label
    return None


def _try_decode(data: bytes, codec: str) -> str | None:
    """Tenta decodificar `data` com `codec` + errors='replace'. None em LookupError."""
    try:
        return data.decode(codec, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return None


def try_decode_sequential(data: bytes) -> list[tuple[EncodingLabel, str]]:
    """Tenta decodificar em todos os encodings; retorna pares (label, text).

    DEF-03: heuristica sequencial. Output e merge — Bloco 03 F3 escaneia
    TODAS as variantes para detectar secrets em encoding-bomb (5 encodings).

    `errors='replace'` aplicado em todas as tentativas (RS-019 enforce).
    Para evitar duplicacao de matches identicos, deduplicamos textos identicos
    (ex: UTF-8 e Latin-1 podem gerar resultados iguais para ASCII puro).
    """
    out: list[tuple[EncodingLabel, str]] = []
    seen_texts: set[str] = set()

    bom = detect_bom(data)
    if bom is not None:
        # com BOM: usa label BOM + decode sem o prefix BOM
        prefix_len = next(len(b) for b, label in BOMS.items() if label == bom)
        bom_codec = {
            "utf-8-bom": "utf-8",
            "utf-16-le": "utf-16-le",
            "utf-16-be": "utf-16-be",
        }[bom]
        text = _try_decode(data[prefix_len:], bom_codec)
        if text is not None and text not in seen_texts:
            out.append((bom, text))
            seen_texts.add(text)

    for enc in _SEQUENTIAL_ENCODINGS:
        if (enc == "utf-8") and bom == "utf-8-bom":
            continue  # ja coberto pela tentativa BOM
        codec_map = {
            "utf-8": "utf-8",
            "utf-16-le": "utf-16-le",
            "utf-16-be": "utf-16-be",
            "utf-7": "utf_7",  # codec name interno do Python
            "latin-1": "latin-1",
        }
        codec_name = codec_map.get(enc)
        if codec_name is None:
            continue
        text = _try_decode(data, codec_name)
        if text is None:
            continue
        if text in seen_texts:
            continue
        out.append((enc, text))
        seen_texts.add(text)
    return out


def classify_encoding(path: Path) -> EncodingLabel:
    """Classifica encoding canonico (sample 8 KB). Retorna 'binary' se null-byte detectado.

    Heuristica:
    1. BOM detection: UTF-8 BOM / UTF-16-LE BOM / UTF-16-BE BOM.
    2. Null-byte fora de BOM (e fora de UTF-16 esperado): 'binary'.
       Excecao: UTF-16-LE/BE sempre tem null-bytes; BOM-detection ja cobriu eles.
    3. UTF-8 strict: se decode passa, 'utf-8'.
    4. UTF-16-LE / UTF-16-BE strict (sem BOM): se decode passa, retorna o label.
    5. Fallback 'latin-1' (sempre decodifica).
    """
    try:
        with open(path, "rb") as fh:
            sample = fh.read(8 * 1024)
    except OSError:
        return "latin-1"  # fallback seguro
    bom = detect_bom(sample)
    if bom is not None:
        return bom
    # null-byte fora de BOM -> trata como binario
    if b"\x00" in sample:
        return "binary"
    # tenta UTF-8 strict
    try:
        sample.decode("utf-8", errors="strict")
        return "utf-8"
    except UnicodeDecodeError:
        pass
    # tenta UTF-16
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            sample.decode(enc, errors="strict")
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


def iter_decoded_variants(data: bytes) -> Iterable[tuple[EncodingLabel, str]]:
    """Generator-friendly wrapper de try_decode_sequential."""
    return iter(try_decode_sequential(data))


__all__ = [
    "BOMS",
    "EncodingLabel",
    "classify_encoding",
    "detect_bom",
    "iter_decoded_variants",
    "try_decode_sequential",
]
