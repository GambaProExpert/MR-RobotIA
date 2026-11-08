"""
Perfiles de servidor LLM. El orden de `PERFILES` importa: llama.cpp va primero porque se
reconoce por una cabecera, sin pedir nada que tenga efectos, y vLLM necesita mirar `/metrics`.
"""
from __future__ import annotations

from mrrobotia.perfiles.base import Identificacion, Op, Perfil
from mrrobotia.perfiles.generico import Generico
from mrrobotia.perfiles.llamacpp import LlamaCpp
from mrrobotia.perfiles.vllm import Vllm

PERFILES = [LlamaCpp(), Vllm()]
GENERICO = Generico()

__all__ = ["GENERICO", "PERFILES", "Identificacion", "Op", "Perfil", "perfil_de", "por_id"]


def por_id(id_perfil):
    """Perfil con ese identificador, o None."""
    for perfil in [*PERFILES, GENERICO]:
        if perfil.id == id_perfil:
            return perfil
    return None


def perfil_de(servidor):
    """Perfil que corresponde a un `ServidorDetectado`; el genérico si no tiene uno propio."""
    return por_id(servidor.tipo) or GENERICO
