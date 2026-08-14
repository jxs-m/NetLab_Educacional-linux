import sys
import os
from pathlib import Path

def recurso_path(caminho_relativo):
    """
    Retorna o caminho absoluto para um recurso, compatível com PyInstaller.
    """
    if hasattr(sys, '_MEIPASS'):
        # Quando rodando como executável (PyInstaller)
        base_path = Path(sys._MEIPASS)
    else:
        # Quando rodando em desenvolvimento (Python normal)
        base_path = Path(__file__).resolve().parent.parent

    return str(base_path / caminho_relativo)