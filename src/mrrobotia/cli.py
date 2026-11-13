#!/usr/bin/env python3
"""
MRRobotIA: defensive posture auditor for self-hosted LLM deployments (bachelor's thesis).

Usage:
  mrrobotia -t target.json [-a] [-o report_prefix] [-s SCANS] [-x SCANS]
  mrrobotia -l
  python -m mrrobotia -t target.json

Environment variables (alternative to the options):
  MRROBOTIA_TARGET  path of the target file if -t/--target is not given.
  MRROBOTIA_ACTIVE  "1"/"true" is the same as -a/--active.

It audits ONLY the infrastructure declared by the target file, which must include the
authorization. Active modules (which interact with the service) are skipped unless
enabled with -a/--active (or MRROBOTIA_ACTIVE) AND permitir_activos=true in the target
file. HYBRID modules (H2, H3...) always do their passive part (network binding, processes,
files) and their active part (network probing) only when active probing is enabled.

Before any module, H2-ID identifies what it is dealing with (server, version, startup
and OS); it always runs. Host analysis (H3) is only done on machines with a llama.cpp or
vLLM server. With -l/--list you can see all the scans and groups.

The audit report and the keys of the target file are in Spanish for now.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

from mrrobotia import herramientas, nucleo
from mrrobotia.modulos.m2_integridad import M2Integridad
from mrrobotia.modulos.m3_configuracion import M3Configuracion
from mrrobotia.modulos.h2_identificacion import H2Identificacion, destino_declarado
from mrrobotia.modulos.h2_exposicion import H2Exposicion
from mrrobotia.modulos.h2_arranque import H2Arranque
from mrrobotia.modulos.h2_cve import H2Cve
from mrrobotia.modulos.h3_ssh import H3Ssh
from mrrobotia.modulos.h3_puertos import H3Puertos
from mrrobotia.modulos.h3_host import H3Host

# La identificación no es un módulo más: corre siempre y primero, y su Contexto lo reciben
# los demás, sea cual sea la selección de --scan.
IDENTIFICACION = H2Identificacion()

# Registro de módulos. H2 va antes de los otros porque su sondeo concreta la autenticación
# y la versión. El prober propio M1 queda sin cablear: su cometido (barrido del endpoint) lo
# asumirá garak en H4.
MODULOS = [M2Integridad(), M3Configuracion(), H2Exposicion(), H2Arranque(), H2Cve(),
           H3Ssh(), H3Puertos(), H3Host()]

# Grupos del selector --scan y --skip (además de las etiquetas individuales de cada
# módulo), con su descripción para --list y --help.
GRUPOS = {
    "host": {"ssh", "ports", "vulns"},                     # la "seguridad del host" (H3)
    "active": {"exposure", "ssh", "ports"},                # módulos con parte activa (NO la habilita)
    "server": {"exposure", "startup", "cve"},              # el servidor LLM en sí
}
DESCRIPCION_GRUPOS = {
    "all": "all scans (default)",
    "host": "host security (H3)",
    "active": "the ones with an active part; they do not enable it",
    "server": "the LLM server: exposure, startup and security advisories",
    "passive": "everything, but with no active check at all",
}
TIPOS_SERVIDOR_LLM = ("llama.cpp", "vllm")
_NOMBRE_TIPO = {"pasivo": "passive", "hibrido": "hybrid", "activo": "active"}


def _etiquetas():
    """Etiquetas de todos los escaneos registrados, identificación incluida."""
    return {m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS] if m.etiqueta_escaneo}


def _ayuda_escaneo():
    """Help text of --scan, generated from the registry so it never gets out of date."""
    etiquetas = ", ".join(m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS])
    grupos = ", ".join(f"{g} ({'+'.join(sorted(GRUPOS[g]))})" if g in GRUPOS else g
                       for g in DESCRIPCION_GRUPOS)
    return (f"Scans to run, comma-separated. Labels: {etiquetas}. Groups: {grupos}. "
            "'passive' forces skipping every active check. The id scan always runs, "
            "first. Default: all. Use -l/--list to see what each one does.")


def _ayuda_excluir():
    return ("Labels or groups to remove from the selection, comma-separated (the same "
            "values as -s/--scan, except all and passive). The id scan cannot be skipped.")


def _expandir(valor):
    """Convierte una lista separada por comas en (etiquetas, desconocidos): las etiquetas a
    las que equivalen las etiquetas y grupos, y los valores que no son ninguna de las dos."""
    etiquetas = _etiquetas()
    seleccion, desconocidos = set(), set()
    for t in (x.strip().lower() for x in (valor or "").split(",")):
        if not t:
            continue
        if t in GRUPOS:
            seleccion |= GRUPOS[t]
        elif t in etiquetas:
            seleccion.add(t)
        else:
            desconocidos.add(t)
    return seleccion, desconocidos


def _resolver_escaneo(valor, excluir=None):
    """Translate --scan and --skip into (selection, force_passive).

    `selection` is the set of scan labels to run, or None = all. `force_passive`
    forces skipping every active check (as if --active were not given). An unknown
    value aborts with the list of valid ones.
    """
    etiquetas = _etiquetas()
    tokens = {t.strip().lower() for t in (valor or "all").split(",") if t.strip()}
    forzar_pasivo = "passive" in tokens
    todo = not (tokens - {"passive"}) or "all" in tokens
    tokens -= {"passive", "all"}
    seleccion, desconocidos = _expandir(",".join(tokens))
    if desconocidos:
        validos = ", ".join(sorted(etiquetas | set(GRUPOS) | {"all", "passive"}))
        sys.exit(f"--scan: unknown value '{sorted(desconocidos)[0]}'. Valid: {validos}")
    if todo:
        seleccion = None
    if excluir:
        quitar, desconocidos = _expandir(excluir)
        if desconocidos:
            malo = sorted(desconocidos)[0]
            if malo in ("all", "passive"):
                sys.exit(f"--skip: '{malo}' cannot be skipped; give specific labels or groups.")
            validos = ", ".join(sorted((etiquetas - {IDENTIFICACION.etiqueta_escaneo}) | set(GRUPOS)))
            sys.exit(f"--skip: unknown value '{malo}'. Valid: {validos}")
        if IDENTIFICACION.etiqueta_escaneo in quitar:
            sys.exit("--skip: the id scan cannot be skipped: it always runs first, "
                     "because the other scans depend on what it identifies.")
        seleccion = (set(etiquetas) if seleccion is None else seleccion) - quitar
    return seleccion, forzar_pasivo


def _listar():
    """Print the available scans and groups."""
    print("Scans (for -s/--scan and -x/--skip):\n")
    for m in [IDENTIFICACION, *MODULOS]:
        externa = "none"
        if m.externa is not None:
            det = herramientas.detectar(m.externa)
            externa = f"{m.externa.nombre} ({'installed' if det.disponible else 'not installed'})"
        print(f"  {m.etiqueta_escaneo}  [{m.nombre}]")
        print(f"      {m.descripcion}")
        extra = [f"type: {_NOMBRE_TIPO.get(m.tipo, m.tipo)}", f"external tool: {externa}"]
        if m.requiere_servidor:
            extra.append("only with a llama.cpp or vLLM server")
        if m is IDENTIFICACION:
            extra.append("always runs, first; cannot be skipped")
        print("      " + "; ".join(extra))
    print("\nGroups:\n")
    for g, texto in DESCRIPCION_GRUPOS.items():
        miembros = f" = {', '.join(sorted(GRUPOS[g]))}" if g in GRUPOS else ""
        print(f"  {g}: {texto}{miembros}")


def _preparar_salida(prefijo):
    """Crea la carpeta de --out si falta y comprueba que se puede escribir en ella.
    Se hace ANTES de escanear: fallar al final perdería toda la auditoría."""
    if prefijo.endswith(("/", "\\")) or not Path(prefijo).name:
        sys.exit("--out is the prefix of the report files (e.g. folder/report), not a folder.")
    carpeta = Path(prefijo).parent
    try:
        carpeta.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=carpeta):
            pass
        for ext in (".json", ".md"):
            if Path(prefijo + ext).is_dir():
                raise IsADirectoryError(prefijo + ext)
    except OSError as e:
        sys.exit(f"--out: cannot create or write in '{carpeta}' ({type(e).__name__}). "
                 "Nothing has been scanned.")


def _ejecutar_aislado(modulo, objetivo):
    """Ejecuta un módulo sin que un fallo suyo aborte la auditoría: se convierte en un
    hallazgo INFO sin_concluir con solo el tipo de la excepción (el mensaje puede llevar
    rutas o datos)."""
    try:
        return modulo.ejecutar(objetivo)
    except Exception as e:
        return [nucleo.Hallazgo(
            modulo.nombre, f"{modulo.nombre}-ERROR", f"El módulo {modulo.nombre} no pudo completarse",
            nucleo.Severidad.INFO, "sin_concluir", type(e).__name__,
            "Repite el escaneo de este módulo y revisa el objetivo y los ficheros que lee.")]


def _hay_servidor_llm(contexto):
    """¿Hay llama.cpp o vLLM identificado, declarado o forzado?"""
    return contexto is not None and any(s.tipo in TIPOS_SERVIDOR_LLM for s in contexto.servidores)


def main():
    ap = argparse.ArgumentParser(prog="mrrobotia", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-t", "--target", help="JSON file with scope and authorization (or the MRROBOTIA_TARGET variable)")
    ap.add_argument("-a", "--active", action="store_true",
                    help="Enable the modules that interact with the service (also requires permitir_activos=true)")
    ap.add_argument("-o", "--out", default="informe_mrrobotia",
                    help="Prefix of the report files; if its folder does not exist, it is created")
    ap.add_argument("-s", "--scan", default="all", help=_ayuda_escaneo().replace("%", "%%"))
    ap.add_argument("-x", "--skip", default=None, help=_ayuda_excluir())
    ap.add_argument("-l", "--list", action="store_true",
                    help="Show the scans and the groups (what they do, whether they are passive or hybrid, "
                         "which external tool they use and whether it is installed) and exit")
    ap.add_argument("--server", choices=["auto", "llama.cpp", "vllm"], default="auto",
                    help="Force the type of server to audit instead of detecting it (default: auto). "
                         "If the detected one differs, a warning is issued and the forced one is used")
    ap.add_argument("--declared-only", action="store_true",
                    help="Audit only the server of the endpoint or port declared in the target file: "
                         "no other candidates are probed and the host's other servers are not audited")
    args = ap.parse_args()

    if args.list:
        _listar()
        return

    ruta_objetivo = args.target or os.environ.get("MRROBOTIA_TARGET")
    if not ruta_objetivo:
        sys.exit("Missing -t/--target or the MRROBOTIA_TARGET variable")

    try:
        objetivo = nucleo.cargar_objetivo(ruta_objetivo)
    except nucleo.ErrorAutorizacion as e:
        sys.exit(f"Authorization denied: {e}")
    except OSError as e:
        sys.exit(f"Cannot read the target file ({type(e).__name__}): {ruta_objetivo}")
    except ValueError:
        sys.exit(f"The target file is not valid JSON: {ruta_objetivo}")

    seleccion, forzar_pasivo = _resolver_escaneo(args.scan, args.skip)
    if args.declared_only and destino_declarado(objetivo).puerto is None:
        sys.exit("--declared-only: the target file declares no server. Set 'endpoint' "
                 "(e.g. http://127.0.0.1:8080) or 'exposicion.puerto', or drop --declared-only.")
    _preparar_salida(args.out)

    informe = nucleo.Informe(objetivo)
    activos_ok = (args.active
                  or os.environ.get("MRROBOTIA_ACTIVE") in ("1", "true", "True")) \
        and objetivo.get("permitir_activos") is True
    if forzar_pasivo:
        activos_ok = False
    informe.pedidos = [m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS]
                       if seleccion is None or m is IDENTIFICACION or m.etiqueta_escaneo in seleccion]
    excluidos = _expandir(args.skip)[0] if args.skip else set()
    if args.declared_only:
        informe.notas.append("Se ha auditado solo el servidor del endpoint o puerto declarado (--declared-only): "
                             "los demás servidores del host no se han identificado ni auditado.")

    IDENTIFICACION.activos_ok = activos_ok
    IDENTIFICACION.servidor_forzado = None if args.server == "auto" else args.server
    IDENTIFICACION.solo_declarado = args.declared_only
    informe.anadir(_ejecutar_aislado(IDENTIFICACION, objetivo))
    informe.modulos_ejecutados.append(IDENTIFICACION.nombre)
    informe.contexto = IDENTIFICACION.contexto
    hay_servidor = _hay_servidor_llm(IDENTIFICACION.contexto)

    for m in MODULOS:
        if seleccion is not None and m.etiqueta_escaneo not in seleccion:
            informe.omitir(m, "excluido con --skip" if m.etiqueta_escaneo in excluidos
                           else "no seleccionado con --scan")
            continue
        m.activos_ok = activos_ok   # los módulos híbridos (p. ej. H2, H3) autogatean su parte activa
        m.contexto = IDENTIFICACION.contexto
        if m.activo and not activos_ok:
            motivo = "módulo activo; requiere --active y permitir_activos=true"
            informe.notas.append(f"{m.nombre} ({m.titulo}) omitido: {motivo}.")
            informe.omitir(m, motivo)
            continue
        if m.requiere_servidor and not hay_servidor:
            informe.notas.append(
                f"{m.nombre} ({m.titulo}) omitido: el análisis del host es solo para máquinas con un "
                "servidor llama.cpp o vLLM y no se ha identificado ninguno. Si lo hay, fuerza el tipo "
                "con --server o con la clave 'servidor' del objetivo.")
            informe.omitir(m, "no se ha identificado un servidor llama.cpp ni vLLM")
            continue
        informe.anadir(_ejecutar_aislado(m, objetivo))
        informe.modulos_ejecutados.append(m.nombre)

    try:
        Path(args.out + ".json").write_text(informe.to_json(), encoding="utf-8")
        Path(args.out + ".md").write_text(informe.to_markdown(), encoding="utf-8")
    except OSError as e:
        sys.exit(f"Could not write the report ({type(e).__name__}) with the prefix '{args.out}'.")
    n = len(informe.hallazgos)
    print(f"MRRobotIA: {n} finding(s). Report in {args.out}.md and {args.out}.json")


if __name__ == "__main__":
    main()
