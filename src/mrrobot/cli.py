#!/usr/bin/env python3
"""
MRRobot — auditor de postura defensiva de despliegues locales de LLM (TFG).

Uso:
  mrrobot --objetivo objetivo.json [--permitir-activos] [--salida informe_mrrobot]
  python -m mrrobot --objetivo objetivo.json

Variables de entorno (alternativa a los parámetros):
  MRROBOT_OBJETIVO          ruta del fichero de objetivo si no se pasa --objetivo.
  MRROBOT_PERMITIR_ACTIVOS  "1"/"true" equivale a --permitir-activos.

Audita SOLO la infraestructura que declara el objetivo, que debe incluir la
autorización. Los módulos activos (que interactúan con el servicio) se omiten salvo
que se habiliten con --permitir-activos (o MRROBOT_PERMITIR_ACTIVOS) Y
permitir_activos=true en el objetivo. H2 (exposición) es HÍBRIDO: la parte pasiva
(enlace de red, entorno, propietario del proceso) corre siempre; la parte activa
(sondeo del endpoint llama.cpp de 'endpoint') solo con el sondeo activo habilitado.
"""
import argparse
import os
import sys
from pathlib import Path

from mrrobot import nucleo
from mrrobot.modulos.m2_integridad import M2Integridad
from mrrobot.modulos.m3_configuracion import M3Configuracion
from mrrobot.modulos.h2_exposicion import H2Exposicion
from mrrobot.modulos.h3_ssh import H3Ssh
from mrrobot.modulos.h3_puertos import H3Puertos
from mrrobot.modulos.h3_host import H3Host

# Registro de módulos. M2/M3 pasivos; H2, H3-SSH y H3-PUERTOS híbridos (parte activa
# autogateada); H3-HOST (Trivy) pasivo. El prober propio M1 queda sin cablear: su
# cometido (barrido del endpoint) lo asumirá garak en H4.
MODULOS = [M2Integridad(), M3Configuracion(), H2Exposicion(),
           H3Ssh(), H3Puertos(), H3Host()]

# Grupos del selector --escaneo (además de las etiquetas individuales de cada módulo).
GRUPOS = {
    "host": {"ssh", "puertos", "vulns"},          # la "seguridad del host" (H3)
    "activo": {"exposicion", "ssh", "puertos"},   # módulos con parte activa (NO la habilita)
}


def _resolver_escaneo(valor):
    """Traduce --escaneo a (seleccion, forzar_pasivo).

    `seleccion` es un conjunto de etiquetas de escaneo a ejecutar, o None = todas.
    `forzar_pasivo` fuerza a omitir toda comprobación activa (como si no hubiera
    --permitir-activos). Un valor desconocido aborta con la lista de válidos.
    """
    etiquetas = {m.etiqueta_escaneo for m in MODULOS if m.etiqueta_escaneo}
    tokens = {t.strip().lower() for t in (valor or "todo").split(",") if t.strip()}
    forzar_pasivo = "pasivo" in tokens
    tokens.discard("pasivo")
    if not tokens or "todo" in tokens:
        return None, forzar_pasivo
    seleccion = set()
    for t in tokens:
        if t in GRUPOS:
            seleccion |= GRUPOS[t]
        elif t in etiquetas:
            seleccion.add(t)
        else:
            validos = ", ".join(sorted(etiquetas | set(GRUPOS) | {"todo", "pasivo"}))
            sys.exit(f"--escaneo: valor desconocido '{t}'. Válidos: {validos}")
    return seleccion, forzar_pasivo


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--objetivo", help="Fichero JSON de alcance y autorización (o la variable MRROBOT_OBJETIVO)")
    ap.add_argument("--permitir-activos", action="store_true",
                    help="Habilita los módulos que interactúan con el servicio (requiere permitir_activos=true)")
    ap.add_argument("--salida", default="informe_mrrobot", help="Prefijo de los ficheros de informe")
    ap.add_argument("--escaneo", default="todo",
                    help="Qué escaneos correr, separados por comas: etiquetas (integridad, "
                         "config, exposicion, ssh, puertos, vulns) o grupos (todo, host, activo, "
                         "pasivo). 'pasivo' fuerza a omitir toda comprobación activa. Por defecto: todo.")
    args = ap.parse_args()

    ruta_objetivo = args.objetivo or os.environ.get("MRROBOT_OBJETIVO")
    if not ruta_objetivo:
        sys.exit("Falta --objetivo o la variable MRROBOT_OBJETIVO")

    try:
        objetivo = nucleo.cargar_objetivo(ruta_objetivo)
    except nucleo.ErrorAutorizacion as e:
        sys.exit(f"Autorización denegada: {e}")

    informe = nucleo.Informe(objetivo)
    seleccion, forzar_pasivo = _resolver_escaneo(args.escaneo)
    activos_ok = (args.permitir_activos
                  or os.environ.get("MRROBOT_PERMITIR_ACTIVOS") in ("1", "true", "True")) \
        and objetivo.get("permitir_activos") is True
    if forzar_pasivo:
        activos_ok = False
    for m in MODULOS:
        if seleccion is not None and m.etiqueta_escaneo not in seleccion:
            continue
        m.activos_ok = activos_ok   # los módulos híbridos (p. ej. H2, H3) autogatean su parte activa
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
