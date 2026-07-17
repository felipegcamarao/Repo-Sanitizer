"""_boilerplate_generator.py — Auto-geracao de boilerplate publicavel (ADR-033).

Gera arquivos minimos quando o destino sanitizado nao possui:
  - pyproject.toml (Python)
  - package.json (Node)
  - Cargo.toml (Rust)
  - go.mod (Go)
  - LICENSE (default MIT, override via flag CLI)

Consumido por: Gate G2 (f4_readme.run_g2_replica_funcional, ADR-032).

Design:
  - Templates 100% in-process; zero deps externos (stdlib + sanitize_slug).
  - Banner explicito em todo arquivo auto-gerado para [NOME] revisar antes
    de publicar.
  - Slug e re-sanitizado pelo `sanitize_slug` canonico (Bloco 03) para
    garantir compatibilidade com regras de naming dos package managers.
  - Para LICENSE, year e injetado (datetime.now().year) com placeholder
    de holder ([NOME] substitui antes de publicar).

ADR-033 (canonizado neste bloco):
  - Auto-gen NAO tenta inferir dependencies reais (out-of-scope; [NOME]
    completa via `pip install -e .` + `pip freeze`).
  - Auto-gen NAO substitui boilerplate ja existente (idempotencia).
  - Auto-gen E sinalizado em SANITIZATION_REPORT seção 'Gate G2 — Replica Funcional'.
"""
from __future__ import annotations

import json
from typing import Literal

from repo_sanitizer.helpers._cross_project_classifier import sanitize_slug

LicenseId = Literal["MIT", "APACHE-2.0", "BSD-3", "GPL-3.0"]

ALLOWED_LICENSES: tuple[LicenseId, ...] = ("MIT", "APACHE-2.0", "BSD-3", "GPL-3.0")

_AUTO_GEN_BANNER_PY = (
    "# [REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]\n"
    "# Este arquivo foi auto-gerado pelo repo-sanitizer-agent (ADR-033)\n"
    "# porque o source-tree nao tinha pyproject.toml. Revise os campos\n"
    "# antes de publicar (em especial: authors, dependencies, version).\n"
)

_AUTO_GEN_BANNER_JSON_HINT = (
    "REPO-SANITIZER NOTICE — INFERRED BOILERPLATE. Revise antes de publicar."
)

_AUTO_GEN_BANNER_TOML = (
    "# [REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]\n"
    "# Auto-gerado pelo repo-sanitizer-agent (ADR-033). Revise antes de publicar.\n"
)

_AUTO_GEN_BANNER_GO = (
    "// [REPO-SANITIZER NOTICE — INFERRED BOILERPLATE]\n"
    "// Auto-gerado pelo repo-sanitizer-agent (ADR-033). Revise antes de publicar.\n"
)


def _sanitize_pkg_name(slug: str) -> str:
    """Aplica sanitize_slug canonico + fallback para 'project' se vazio.

    Garante compatibilidade com naming-rules de pyproject/package.json/Cargo:
      - kebab-case ASCII
      - apenas [a-z0-9.-]
      - sem hifens nas pontas
    Slugs vazios (ex.: `extract_project_slug` devolve UNKNOWN_PROJECT_SENTINEL
    mas chamador pode passar string vazia) sao mapeados para 'project'.
    """
    cleaned = sanitize_slug(slug)
    if not cleaned:
        return "project"
    return cleaned


def generate_pyproject(slug: str) -> str:
    """Gera pyproject.toml minimo para Python projects (PEP 517/setuptools).

    Args:
        slug: project slug (sanitizado internamente para package-name format).

    Returns:
        Conteudo completo do pyproject.toml, com banner explicito.
    """
    pkg_name = _sanitize_pkg_name(slug)
    return (
        _AUTO_GEN_BANNER_PY
        + "\n"
        + "[build-system]\n"
        + 'requires = ["setuptools>=68.0"]\n'
        + 'build-backend = "setuptools.build_meta"\n'
        + "\n"
        + "[project]\n"
        + f'name = "{pkg_name}"\n'
        + 'version = "0.0.0"\n'
        + 'description = "TODO: descreva o projeto antes de publicar."\n'
        + 'requires-python = ">=3.11"\n'
        + 'authors = [{name = "TODO <SEU-NOME>", email = "todo@example.com"}]\n'
        + "dependencies = []\n"
        + "\n"
        + "[tool.setuptools.packages.find]\n"
        + 'where = ["src"]\n'
    )


def generate_package_json(slug: str) -> str:
    """Gera package.json minimo para Node projects.

    Args:
        slug: project slug (sanitizado para npm-compatible name).

    Returns:
        Conteudo JSON serializado com indent=2 + banner em "_notice".
    """
    pkg_name = _sanitize_pkg_name(slug)
    payload: dict[str, object] = {
        "_notice": _AUTO_GEN_BANNER_JSON_HINT,
        "name": pkg_name,
        "version": "0.0.0",
        "private": True,
        "description": "TODO: descreva o projeto antes de publicar.",
        "scripts": {"test": "echo todo"},
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def generate_cargo_toml(slug: str) -> str:
    """Gera Cargo.toml minimo para Rust projects.

    Args:
        slug: project slug (sanitizado para crate-name format).

    Returns:
        Conteudo TOML com [package] section + banner.
    """
    pkg_name = _sanitize_pkg_name(slug)
    return (
        _AUTO_GEN_BANNER_TOML
        + "\n"
        + "[package]\n"
        + f'name = "{pkg_name}"\n'
        + 'version = "0.0.0"\n'
        + 'edition = "2021"\n'
        + 'description = "TODO: descreva o projeto antes de publicar."\n'
        + "\n"
        + "[dependencies]\n"
    )


def generate_go_mod(slug: str) -> str:
    """Gera go.mod minimo para Go projects.

    Args:
        slug: project slug (usado como module path). Para go.mod, slug e
            mantido em formato com hifens (kebab-case) — diferente de Python
            onde se prefere snake_case, Go aceita ambos no module path.

    Returns:
        Conteudo go.mod com module + go 1.21 + banner.
    """
    pkg_name = _sanitize_pkg_name(slug)
    return (
        _AUTO_GEN_BANNER_GO
        + "\n"
        + f"module {pkg_name}\n"
        + "\n"
        + "go 1.21\n"
    )


_LICENSE_TEXTS: dict[LicenseId, str] = {
    "MIT": (
        "MIT License\n\n"
        "Copyright (c) {year} TODO <TITULAR-DO-COPYRIGHT>\n\n"
        "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
        'of this software and associated documentation files (the "Software"), to deal\n'
        "in the Software without restriction, including without limitation the rights\n"
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
        "copies of the Software, and to permit persons to whom the Software is\n"
        "furnished to do so, subject to the following conditions:\n\n"
        "The above copyright notice and this permission notice shall be included in all\n"
        "copies or substantial portions of the Software.\n\n"
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
        "SOFTWARE.\n"
    ),
    "APACHE-2.0": (
        "Apache License\n"
        "Version 2.0, January 2004\n"
        "http://www.apache.org/licenses/\n\n"
        "Copyright {year} TODO <TITULAR-DO-COPYRIGHT>\n\n"
        'Licensed under the Apache License, Version 2.0 (the "License"); you may not\n'
        "use this file except in compliance with the License. You may obtain a copy of\n"
        "the License at\n\n"
        "    http://www.apache.org/licenses/LICENSE-2.0\n\n"
        "Unless required by applicable law or agreed to in writing, software\n"
        'distributed under the License is distributed on an "AS IS" BASIS, WITHOUT\n'
        "WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the\n"
        "License for the specific language governing permissions and limitations under\n"
        "the License.\n"
    ),
    "BSD-3": (
        "BSD 3-Clause License\n\n"
        "Copyright (c) {year}, TODO <TITULAR-DO-COPYRIGHT>\n"
        "All rights reserved.\n\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions are met:\n\n"
        "1. Redistributions of source code must retain the above copyright notice,\n"
        "   this list of conditions and the following disclaimer.\n\n"
        "2. Redistributions in binary form must reproduce the above copyright notice,\n"
        "   this list of conditions and the following disclaimer in the documentation\n"
        "   and/or other materials provided with the distribution.\n\n"
        "3. Neither the name of the copyright holder nor the names of its contributors\n"
        "   may be used to endorse or promote products derived from this software\n"
        "   without specific prior written permission.\n\n"
        'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"\n'
        "AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE\n"
        "COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,\n"
        "EXEMPLARY, OR CONSEQUENTIAL DAMAGES.\n"
    ),
    "GPL-3.0": (
        "GNU GENERAL PUBLIC LICENSE\n"
        "Version 3, 29 June 2007\n\n"
        "Copyright (C) {year} TODO <TITULAR-DO-COPYRIGHT>\n\n"
        "This program is free software: you can redistribute it and/or modify it under\n"
        "the terms of the GNU General Public License as published by the Free Software\n"
        "Foundation, either version 3 of the License, or (at your option) any later\n"
        "version.\n\n"
        "This program is distributed in the hope that it will be useful, but WITHOUT\n"
        "ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n"
        "FOR A PARTICULAR PURPOSE. See the GNU General Public License for more\n"
        "details.\n\n"
        "You should have received a copy of the GNU General Public License along with\n"
        "this program. If not, see <https://www.gnu.org/licenses/>.\n"
    ),
}

_LICENSE_BANNER = (
    "[REPO-SANITIZER NOTICE — INFERRED LICENSE]\n"
    "Auto-gerado pelo repo-sanitizer-agent (ADR-033). Default = MIT.\n"
    "Substitua 'TODO <TITULAR-DO-COPYRIGHT>' pelo holder real antes de publicar.\n"
    "Para mudar a licenca, regere o destino com a flag --license=<ID>.\n\n"
)


def generate_license(license_id: LicenseId, year: int) -> str:
    """Gera LICENSE com banner + texto canonico.

    Args:
        license_id: um de {"MIT", "APACHE-2.0", "BSD-3", "GPL-3.0"}.
        year: ano (4 digitos) para copyright.

    Returns:
        Conteudo do arquivo LICENSE, com banner explicito no topo.

    Raises:
        ValueError: se license_id nao for um dos 4 suportados.
    """
    if license_id not in _LICENSE_TEXTS:
        raise ValueError(
            f"license_id invalido: {license_id!r}. "
            f"Validos: {ALLOWED_LICENSES}"
        )
    body = _LICENSE_TEXTS[license_id].format(year=year)
    return _LICENSE_BANNER + body


# ===========================================================================
# .gitignore ROBUSTO no destino (v1.2.0 / MV-07 / RS-NEW-044 / ADR-011 reuso)
# ===========================================================================
# Bloco canonico HARDCODED de entradas que TODO destino sanitizado deve ignorar,
# anexado por MERGE ADITIVO ao `.gitignore` do destino (nunca overwrite cego —
# mitigacao §5-10 / MV07-C). Fecha C-V11-05 ao garantir `.sanitizer-state.json`
# no `.gitignore`. Fonte de verdade dos caches = consistente com a lista
# canonica `f1_filter.GROUP_A_PATTERNS` (MV-01) mas expressa como GLOBS de
# `.gitignore` (sintaxe de gitignore, nao regex) — documentada aqui como
# constante versionada (RS-NEW-039 + RS-NEW-044).
#
# NUNCA inclui valor literal de segredo/PII (RS-005); so nomes de artefatos.

_GITIGNORE_BANNER = "# === repo-sanitizer-agent (ADR-011 / MV-07) — entradas canonicas ==="
_GITIGNORE_BANNER_END = "# === fim das entradas repo-sanitizer-agent ==="

# Artefatos do PROPRIO sanitizador que NUNCA devem ser versionados pelo destino
# (fecha C-V11-05: `.sanitizer-state.json` vaza paths internos/slug/contagens).
SANITIZER_GITIGNORE_ENTRIES: tuple[str, ...] = (
    ".sanitizer-state.json",
    ".sanitizer-allow",
    "/Relatorios/",
    "audit-log.jsonl",
    "SANITIZATION_REPORT_*.md",
    "FILTER_DIFF_*.md",
)

# Caches/lixo de execucao canonicos (espelha MV-01 / GROUP_A_PATTERNS como globs
# de gitignore). Diretorios com `/` no fim; extensoes com `*.ext`.
CACHE_GITIGNORE_ENTRIES: tuple[str, ...] = (
    # Ambientes virtuais / dependencias
    ".venv/",
    "venv/",
    "env/",
    "node_modules/",
    "__pypackages__/",
    # Caches Python / type / lint / coverage
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".tox/",
    ".nox/",
    ".hypothesis/",
    ".coverage",
    "coverage.xml",
    "htmlcov/",
    # Build outputs / metadata
    "dist/",
    "build/",
    "target/",
    "*.egg-info/",
    "*.pdb",
    "*.class",
    "*.o",
    "*.obj",
    # Caches JS / bundlers
    ".cache/",
    ".parcel-cache/",
    ".turbo/",
    ".svelte-kit/",
    ".next/",
    ".nyc_output/",
    ".eslintcache",
    ".stylelintcache",
    "*.tsbuildinfo",
    # Infra
    ".terraform/",
    ".gradle/",
    # Notebooks / SO / editor
    ".ipynb_checkpoints/",
    ".DS_Store",
    "Thumbs.db",
    "*.swp",
    "*.log",
    # Secrets de ambiente (defesa-em-camadas; C1 ja os exclui no walk)
    ".env",
    ".env.*",
)

# Ordem canonica do bloco anexado (sanitizador primeiro — mais critico p/ C-V11-05).
GITIGNORE_CANONICAL_ENTRIES: tuple[str, ...] = (
    SANITIZER_GITIGNORE_ENTRIES + CACHE_GITIGNORE_ENTRIES
)


def generate_gitignore_additions() -> str:
    """Bloco canonico de entradas `.gitignore` (MV-07 / RS-NEW-044).

    Retorna o bloco completo (banner + entradas + banner-fim) pronto para ser
    escrito quando o destino NAO tem `.gitignore`, OU usado como fonte do
    conjunto de entradas para `merge_gitignore` (merge aditivo). Inclui
    `.sanitizer-state.json` (fecha C-V11-05) + caches canonicos (MV-01) +
    artefatos do proprio sanitizador.

    Zero-literal: so nomes de artefatos/caches; nunca valor de segredo (RS-005).
    """
    lines = [_GITIGNORE_BANNER, *GITIGNORE_CANONICAL_ENTRIES, _GITIGNORE_BANNER_END, ""]
    return "\n".join(lines)


def merge_gitignore(existing: str, *, additions: tuple[str, ...] | None = None) -> str:
    """Merge ADITIVO: anexa entradas canonicas faltantes ao `.gitignore` do autor.

    NUNCA sobrescreve nem reordena o conteudo existente (preserva regras do
    autor — mitigacao §5-10 / MV07-C). Apenas anexa as entradas canonicas que
    AINDA NAO estao presentes (dedup por linha exata, ignorando espacos a
    direita e comentarios). IDEMPOTENTE: rodar 2x nao duplica nada.

    Args:
        existing: conteudo atual do `.gitignore` do destino (pode ser vazio).
        additions: conjunto opcional de entradas a garantir (default =
            `GITIGNORE_CANONICAL_ENTRIES`).

    Returns:
        Conteudo final do `.gitignore` (existing preservado + entradas novas
        anexadas sob o banner). Se nada falta, retorna `existing` inalterado.
    """
    want = additions if additions is not None else GITIGNORE_CANONICAL_ENTRIES

    # Conjunto de linhas ja presentes (normalizado: strip de espacos a direita).
    # Comparacao por linha EXATA (uma entrada `dist/` ja cobre futuras `dist/`).
    present: set[str] = set()
    for raw in existing.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        present.add(stripped)

    missing = [entry for entry in want if entry not in present]
    if not missing:
        # Idempotencia: todas canonicas ja presentes -> nada a fazer.
        return existing

    # Preserva o conteudo do autor; anexa bloco canonico com banner ao final.
    base = existing.rstrip("\n")
    block_lines: list[str] = []
    if base:
        block_lines.append("")  # linha em branco separadora
    block_lines.append(_GITIGNORE_BANNER)
    block_lines.extend(missing)
    block_lines.append(_GITIGNORE_BANNER_END)
    block_lines.append("")  # newline final
    return (base + "\n" if base else "") + "\n".join(block_lines)


__all__ = [
    "ALLOWED_LICENSES",
    "CACHE_GITIGNORE_ENTRIES",
    "GITIGNORE_CANONICAL_ENTRIES",
    "SANITIZER_GITIGNORE_ENTRIES",
    "LicenseId",
    "generate_cargo_toml",
    "generate_gitignore_additions",
    "generate_go_mod",
    "generate_license",
    "generate_package_json",
    "generate_pyproject",
    "merge_gitignore",
]
