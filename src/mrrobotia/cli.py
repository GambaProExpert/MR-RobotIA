#!/usr/bin/env python3
"""
MRRobotIA — auditor de postura defensiva de despliegues locales de LLM (TFG).

Uso:
  mrrobotia --objetivo objetivo.json [--permitir-activos] [--salida informe_mrrobotia]
  mrrobotia --listar
  python -m mrrobotia --objetivo objetivo.json

Variables de entorno (alternativa a los parámetros):
  MRROBOTIA_OBJETIVO          ruta del fichero de objetivo si no se pasa --objetivo.
  MRROBOTIA_PERMITIR_ACTIVOS  "1"/"true" equivale a --permitir-activos.

Audita SOLO la infraestructura que declara el objetivo, que debe incluir la
autorización. Los módulos activos (que interactúan con el servicio) se omiten salvo
que se habiliten con --permitir-activos (o MRROBOTIA_PERMITIR_ACTIVOS) Y
permitir_activos=true en el objetivo. Los módulos HÍBRIDOS (H2, H3...) hacen siempre su
parte pasiva (enlace de red, procesos, ficheros) y su parte activa (sondeo por red) solo
con el sondeo activo habilitado.

Antes de cualquier módulo, H2-ID identifica con qué se está tratando (servidor, versión,
arranque y SO); corre siempre. El análisis del host (H3) solo se hace en máquinas con un
servidor llama.cpp o vLLM. Con --listar se ven todos los escaneos y grupos.
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
# los demás, sea cual sea la selección de --escaneo.
IDENTIFICACION = H2Identificacion()

# Registro de módulos. H2 va antes de los otros porque su sondeo concreta la autenticación
# y la versión. El prober propio M1 queda sin cablear: su cometido (barrido del endpoint) lo
# asumirá garak en H4.
MODULOS = [M2Integridad(), M3Configuracion(), H2Exposicion(), H2Arranque(), H2Cve(),
           H3Ssh(), H3Puertos(), H3Host()]

# Grupos del selector --escaneo y --excluir (además de las etiquetas individuales de cada
# módulo), con su descripción para --listar y --help.
GRUPOS = {
    "host": {"ssh", "puertos", "vulns"},                   # la "seguridad del host" (H3)
    "activo": {"exposicion", "ssh", "puertos"},            # módulos con parte activa (NO la habilita)
    "servidor": {"exposicion", "arranque", "cve"},         # el servidor LLM en sí
}
DESCRIPCION_GRUPOS = {
    "todo": "todos los escaneos (por defecto)",
    "host": "seguridad del host (H3)",
    "activo": "los que tienen parte activa; no la habilitan",
    "servidor": "el servidor LLM: exposición, arranque y avisos de seguridad",
    "pasivo": "todo, pero sin ninguna comprobación activa",
}
TIPOS_SERVIDOR_LLM = ("llama.cpp", "vllm")
_NOMBRE_TIPO = {"pasivo": "pasivo", "hibrido": "híbrido", "activo": "activo"}


def _etiquetas():
    """Etiquetas de todos los escaneos registrados, identificación incluida."""
    return {m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS] if m.etiqueta_escaneo}


def _ayuda_escaneo():
    """Texto de ayuda de --escaneo, generado del registro para que no se desfase."""
    etiquetas = ", ".join(m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS])
    grupos = ", ".join(f"{g} ({'+'.join(sorted(GRUPOS[g]))})" if g in GRUPOS else g
                       for g in DESCRIPCION_GRUPOS)
    return (f"Qué escaneos correr, separados por comas. Etiquetas: {etiquetas}. Grupos: {grupos}. "
            "'pasivo' fuerza a omitir toda comprobación activa. La identificación corre siempre, "
            "primero. Por defecto: todo. Usa --listar para ver qué hace cada uno.")


def _ayuda_excluir():
    return ("Etiquetas o grupos que quitar de la selección, separados por comas (los mismos "
            "valores que --escaneo, salvo todo y pasivo). La identificación no se puede excluir.")


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
    """Traduce --escaneo y --excluir a (seleccion, forzar_pasivo).

    `seleccion` es el conjunto de etiquetas de escaneo a ejecutar, o None = todas.
    `forzar_pasivo` fuerza a omitir toda comprobación activa (como si no hubiera
    --permitir-activos). Un valor desconocido aborta con la lista de válidos.
    """
    etiquetas = _etiquetas()
    tokens = {t.strip().lower() for t in (valor or "todo").split(",") if t.strip()}
    forzar_pasivo = "pasivo" in tokens
    todo = not (tokens - {"pasivo"}) or "todo" in tokens
    tokens -= {"pasivo", "todo"}
    seleccion, desconocidos = _expandir(",".join(tokens))
    if desconocidos:
        validos = ", ".join(sorted(etiquetas | set(GRUPOS) | {"todo", "pasivo"}))
        sys.exit(f"--escaneo: valor desconocido '{sorted(desconocidos)[0]}'. Válidos: {validos}")
    if todo:
        seleccion = None
    if excluir:
        quitar, desconocidos = _expandir(excluir)
        if desconocidos:
            malo = sorted(desconocidos)[0]
            if malo in ("todo", "pasivo"):
                sys.exit(f"--excluir: '{malo}' no se puede excluir; indica etiquetas o grupos concretos.")
            validos = ", ".join(sorted((etiquetas - {IDENTIFICACION.etiqueta_escaneo}) | set(GRUPOS)))
            sys.exit(f"--excluir: valor desconocido '{malo}'. Válidos: {validos}")
        if IDENTIFICACION.etiqueta_escaneo in quitar:
            sys.exit("--excluir: la identificación no se puede excluir: corre siempre y primero, "
                     "porque los demás escaneos dependen de lo que identifica.")
        seleccion = (set(etiquetas) if seleccion is None else seleccion) - quitar
    return seleccion, forzar_pasivo


def _listar():
    """Imprime los escaneos y los grupos disponibles."""
    print("Escaneos (para --escaneo y --excluir):\n")
    for m in [IDENTIFICACION, *MODULOS]:
        externa = "ninguna"
        if m.externa is not None:
            det = herramientas.detectar(m.externa)
            externa = f"{m.externa.nombre} ({'instalada' if det.disponible else 'no instalada'})"
        print(f"  {m.etiqueta_escaneo}  [{m.nombre}]")
        print(f"      {m.descripcion}")
        extra = [f"tipo: {_NOMBRE_TIPO.get(m.tipo, m.tipo)}", f"herramienta externa: {externa}"]
        if m.requiere_servidor:
            extra.append("solo con un servidor llama.cpp o vLLM")
        if m is IDENTIFICACION:
            extra.append("corre siempre, primero; no se puede excluir")
        print("      " + "; ".join(extra))
    print("\nGrupos:\n")
    for g, texto in DESCRIPCION_GRUPOS.items():
        miembros = f" = {', '.join(sorted(GRUPOS[g]))}" if g in GRUPOS else ""
        print(f"  {g}: {texto}{miembros}")


def _preparar_salida(prefijo):
    """Crea la carpeta de --salida si falta y comprueba que se puede escribir en ella.
    Se hace ANTES de escanear: fallar al final perdería toda la auditoría."""
    if prefijo.endswith(("/", "\\")) or not Path(prefijo).name:
        sys.exit("--salida es el prefijo de los ficheros del informe (p. ej. carpeta/informe), no una carpeta.")
    carpeta = Path(prefijo).parent
    try:
        carpeta.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=carpeta):
            pass
        for ext in (".json", ".md"):
            if Path(prefijo + ext).is_dir():
                raise IsADirectoryError(prefijo + ext)
    except OSError as e:
        sys.exit(f"--salida: no se puede crear o escribir en '{carpeta}' ({type(e).__name__}). "
                 "No se ha escaneado nada.")


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
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--objetivo", help="Fichero JSON de alcance y autorización (o la variable MRROBOTIA_OBJETIVO)")
    ap.add_argument("--permitir-activos", action="store_true",
                    help="Habilita los módulos que interactúan con el servicio (requiere permitir_activos=true)")
    ap.add_argument("--salida", default="informe_mrrobotia",
                    help="Prefijo de los ficheros de informe; si su carpeta no existe, se crea")
    ap.add_argument("--escaneo", default="todo", help=_ayuda_escaneo().replace("%", "%%"))
    ap.add_argument("--excluir", default=None, help=_ayuda_excluir())
    ap.add_argument("--listar", action="store_true",
                    help="Muestra los escaneos y los grupos (qué hacen, si son pasivos o híbridos, "
                         "qué herramienta externa usan y si está instalada) y termina")
    ap.add_argument("--servidor", choices=["auto", "llama.cpp", "vllm"], default="auto",
                    help="Fuerza el tipo de servidor a auditar en lugar de detectarlo (por defecto: auto). "
                         "Si lo detectado difiere, se avisa y se usa lo forzado")
    ap.add_argument("--solo-declarado", action="store_true",
                    help="Audita solo el servidor del endpoint o puerto declarado en el objetivo: "
                         "no se prueban otros candidatos ni se auditan los demás servidores del host")
    args = ap.parse_args()

    if args.listar:
        _listar()
        return

    ruta_objetivo = args.objetivo or os.environ.get("MRROBOTIA_OBJETIVO")
    if not ruta_objetivo:
        sys.exit("Falta --objetivo o la variable MRROBOTIA_OBJETIVO")

    try:
        objetivo = nucleo.cargar_objetivo(ruta_objetivo)
    except nucleo.ErrorAutorizacion as e:
        sys.exit(f"Autorización denegada: {e}")
    except OSError as e:
        sys.exit(f"No se puede leer el objetivo ({type(e).__name__}): {ruta_objetivo}")
    except ValueError:
        sys.exit(f"El objetivo no es un JSON válido: {ruta_objetivo}")

    seleccion, forzar_pasivo = _resolver_escaneo(args.escaneo, args.excluir)
    if args.solo_declarado and destino_declarado(objetivo).puerto is None:
        sys.exit("--solo-declarado: el objetivo no declara ningún servidor. Indica 'endpoint' "
                 "(p. ej. http://127.0.0.1:8080) o 'exposicion.puerto', o quita --solo-declarado.")
    _preparar_salida(args.salida)

    informe = nucleo.Informe(objetivo)
    activos_ok = (args.permitir_activos
                  or os.environ.get("MRROBOTIA_PERMITIR_ACTIVOS") in ("1", "true", "True")) \
        and objetivo.get("permitir_activos") is True
    if forzar_pasivo:
        activos_ok = False
    informe.pedidos = [m.etiqueta_escaneo for m in [IDENTIFICACION, *MODULOS]
                       if seleccion is None or m is IDENTIFICACION or m.etiqueta_escaneo in seleccion]
    excluidos = _expandir(args.excluir)[0] if args.excluir else set()
    if args.solo_declarado:
        informe.notas.append("Se ha auditado solo el servidor del endpoint o puerto declarado (--solo-declarado): "
                             "los demás servidores del host no se han identificado ni auditado.")

    IDENTIFICACION.activos_ok = activos_ok
    IDENTIFICACION.servidor_forzado = None if args.servidor == "auto" else args.servidor
    IDENTIFICACION.solo_declarado = args.solo_declarado
    informe.anadir(_ejecutar_aislado(IDENTIFICACION, objetivo))
    informe.modulos_ejecutados.append(IDENTIFICACION.nombre)
    informe.contexto = IDENTIFICACION.contexto
    hay_servidor = _hay_servidor_llm(IDENTIFICACION.contexto)

    for m in MODULOS:
        if seleccion is not None and m.etiqueta_escaneo not in seleccion:
            informe.omitir(m, "excluido con --excluir" if m.etiqueta_escaneo in excluidos
                           else "no seleccionado con --escaneo")
            continue
        m.activos_ok = activos_ok   # los módulos híbridos (p. ej. H2, H3) autogatean su parte activa
        m.contexto = IDENTIFICACION.contexto
        if m.activo and not activos_ok:
            motivo = "módulo activo; requiere --permitir-activos y permitir_activos=true"
            informe.notas.append(f"{m.nombre} ({m.titulo}) omitido: {motivo}.")
            informe.omitir(m, motivo)
            continue
        if m.requiere_servidor and not hay_servidor:
            informe.notas.append(
                f"{m.nombre} ({m.titulo}) omitido: el análisis del host es solo para máquinas con un "
                "servidor llama.cpp o vLLM y no se ha identificado ninguno. Si lo hay, fuerza el tipo "
                "con --servidor o con la clave 'servidor' del objetivo.")
            informe.omitir(m, "no se ha identificado un servidor llama.cpp ni vLLM")
            continue
        informe.anadir(_ejecutar_aislado(m, objetivo))
        informe.modulos_ejecutados.append(m.nombre)

    try:
        Path(args.salida + ".json").write_text(informe.to_json(), encoding="utf-8")
        Path(args.salida + ".md").write_text(informe.to_markdown(), encoding="utf-8")
    except OSError as e:
        sys.exit(f"No se pudo escribir el informe ({type(e).__name__}) con el prefijo '{args.salida}'.")
    n = len(informe.hallazgos)
    print(f"MRRobotIA: {n} hallazgo(s). Informe en {args.salida}.md y {args.salida}.json")


if __name__ == "__main__":
    main()
