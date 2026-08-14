"""
Utilitários compartilhados para escala de fonte da interface NetLab.
"""

from __future__ import annotations

import re

FONTE_TAMANHO_MIN = 8
FONTE_TAMANHO_MAX = 20
LIMITES_FONTE = (FONTE_TAMANHO_MIN, FONTE_TAMANHO_MAX)

# Referência visual padrão: 11px no QSS ≈ 10pt na interface
FONTE_REF_PT = 10
FONTE_REF_PX = 11

_RE_FONTE_PX = re.compile(r"font-size:\s*(\d+)px", re.IGNORECASE)


def clamp_fonte(tamanho) -> int:
    """Restringe o tamanho de fonte ao intervalo permitido (8–20 pt)."""
    return max(FONTE_TAMANHO_MIN, min(FONTE_TAMANHO_MAX, int(tamanho)))


def px_para_pt(px: int, tamanho_base_pt: int = FONTE_REF_PT) -> int:
    """Converte pixels de referência do QSS para pontos proporcionais."""
    return max(FONTE_TAMANHO_MIN, round(px * tamanho_base_pt / FONTE_REF_PX))


def escalar_css_fonte(css: str, tamanho_base_pt: int) -> str:
    """Substitui todas as ocorrências de font-size: Npx por pontos escalados."""
    tamanho_base_pt = clamp_fonte(tamanho_base_pt)

    def _substituir(match: re.Match) -> str:
        px = int(match.group(1))
        return f"font-size: {px_para_pt(px, tamanho_base_pt)}pt"

    return _RE_FONTE_PX.sub(_substituir, css)
