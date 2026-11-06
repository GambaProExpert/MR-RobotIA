#!/usr/bin/env python3
"""
MRRobot — auditor de postura defensiva de despliegues locales de LLM (TFG).

Uso:
  mrrobot --objetivo objetivo.json [--permitir-activos] [--salida informe_mrrobot]
  python -m mrrobot --objetivo objetivo.json

Audita SOLO la infraestructura que declara el objetivo, que debe incluir la
autorización. Los módulos activos (que interactúan con el servicio) se omiten salvo
que se pasen --permitir-activos y permitir_activos=true en el objetivo.
"""
import argparse
import sys
from pathlib import Path

from mrrobot import nucleo
from mrrobot.modulos.m2_integridad import M2Integridad
from mrrobot.modulos.m3_configuracion import M3Configuracion

# Registro de módulos. Se irán añadiendo M1, M4 y M5 en su forma defensiva.
MODULOS = [M2Integridad(), M3Configuracion()]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--objetivo", required=True, help="Fichero JSON de alcance y autorización")
    ap.add_argument("--permitir-activos", action="store_true",
                    help="Habilita los módulos que interactúan con el servicio (requiere permitir_activos=true)")
    ap.add_argument("--salida", default="informe_mrrobot", help="Prefijo de los ficheros de informe")
    args = ap.parse_args()

    try:
        objetivo = nucleo.cargar_objetivo(args.objetivo)
    except nucleo.ErrorAutorizacion as e:
        sys.exit(f"Autorización denegada: {e}")

    informe = nucleo.Informe(objetivo)
    activos_ok = args.permitir_activos and objetivo.get("permitir_activos") is True
    for m in MODULOS:
        if m.activo and not activos_ok:
            informe.notas.append(
                f"{m.nombre} ({m.titulo}) omitido: módulo activo; requiere --permitir-activos y permitir_activos=true.")
            continue
        informe.anadir(m.ejecutar(objetivo))
        informe.modulos_ejecutados.append(m.nombre)

    Path(args.salida + ".json").write_text(informe.to_json(), encoding="utf-8")
    Path(args.salida + ".md").write_text(informe.to_markdown(), encoding="utf-8")
    n = len(informe.hallazgos)
    print(f"MRRobot: {n} hallazgo(s). Informe en {args.salida}.md y {args.salida}.json")


if __name__ == "__main__":
    main()
