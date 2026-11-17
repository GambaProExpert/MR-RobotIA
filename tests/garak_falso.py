"""garak falso para las pruebas herméticas de H4: acepta los mismos argumentos que garak 0.17 y
escribe, en `reporting.report_dir` de la configuración recibida, un informe y un hitlog copiados de
las fixtures (capturas reales saneadas). No usa red ni modelo.

Modos (variable GARAK_FALSO_MODO): ok, sin_completion, exit1, exit0_sin_informe, timeout, sin_clave.
GARAK_FALSO_REGISTRO: ruta de un JSON donde deja los argumentos, la configuración y las variables
de entorno que le llegaron (para comprobar por dónde viaja la clave).
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "garak"
INFORME = FIXTURES / "garak_0.17.1_openai_compat.report.jsonl"
HITLOG = FIXTURES / "garak_0.17.1_openai_compat.hitlog.jsonl"
BANNER = ("garak LLM vulnerability scanner v" + os.environ.get("GARAK_FALSO_VERSION", "0.17.1")
          + " ( https://github.com/NVIDIA/garak ) at 2026-11-17T17:00:00")
LISTA_POR_DEFECTO = ["dan.DanInTheWild", "encoding.InjectBase64", "goodside.WhoIsRiley",
                     "latentinjection.LatentInjectionReport", "promptinject.HijackHateHumans",
                     "sysprompt_extraction.SystemPromptExtraction", "web_injection.MarkdownXSS",
                     "atkgen.Tox", "lmrc.Bullying"]
VARIABLES = ("OPENAICOMPATIBLE_API_KEY", "REST_API_KEY", "OPENAI_API_KEY", "MIKLAVE", "MRROBOTIA_API_KEY",
             "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "HF_HOME", "HF_HUB_OFFLINE", "PYTHONUTF8")


def argumento(argv, nombre):
    return argv[argv.index(nombre) + 1] if nombre in argv else None


def listar(spec):
    lista = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("-"):
            quitar = item[1:].removeprefix("probes.")
            lista = [s for s in lista if s != quitar]
        elif "nada" in item:
            continue
        elif item.startswith(("tier:", "tag:")) or item == "probes":
            lista += [s for s in LISTA_POR_DEFECTO if s not in lista]
        else:
            nombre = item.removeprefix("probes.")
            lista += [s for s in LISTA_POR_DEFECTO if (s == nombre or s.startswith(nombre + ".")) and s not in lista]
            if not any(s.startswith(nombre) for s in LISTA_POR_DEFECTO) and "." in nombre:
                lista.append(nombre)
    return lista


def main():
    argv = sys.argv[1:]
    modo = os.environ.get("GARAK_FALSO_MODO", "ok")
    if "--version" in argv:
        print(BANNER)
        return 0
    if "--list_probes" in argv:
        print(BANNER)
        lista = listar(argument_spec(argv))
        if not lista:
            print("No probes match the provided filter")
        for s in lista:
            print(f"\x1b[1m\x1b[93mprobes: \x1b[0m{s}")
        return 0

    config = json.loads(Path(argumento(argv, "--config")).read_text(encoding="utf-8"))
    registro = os.environ.get("GARAK_FALSO_REGISTRO")
    if registro:
        Path(registro).write_text(json.dumps({
            "argv": argv, "config": config, "env": {k: os.environ.get(k) for k in VARIABLES}}), encoding="utf-8")
    print(BANNER)
    if modo == "sin_clave":
        print("\U0001F6D1 Put the OpenAICompatible API key in the OPENAICOMPATIBLE_API_KEY environment variable")
        return 0
    if modo == "exit0_sin_informe":
        print("❌Unknown run.spec❌")
        return 0
    destino = Path(config["reporting"]["report_dir"])
    destino.mkdir(parents=True, exist_ok=True)
    prefijo = argumento(argv, "--report_prefix") or "garak"
    lineas = INFORME.read_text(encoding="utf-8").splitlines()
    if modo == "exit1":
        lineas = [x for x in lineas if json.loads(x)["entry_type"] in ("init", "start_run setup")]
        (destino / f"{prefijo}.report.jsonl").write_text("\n".join(lineas) + "\n", encoding="utf-8")
        print("Traceback (most recent call last):\nrequests.exceptions.ConnectionError: "
              "HTTPConnectionPool(host='127.0.0.1', port=1): Max retries exceeded with url: /v1/")
        return 1
    if modo == "sin_completion":
        lineas = [x for x in lineas if json.loads(x)["entry_type"] != "completion"]
    if modo == "timeout":
        hijo = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        if registro:
            Path(registro + ".hijo").write_text(str(hijo.pid), encoding="utf-8")
        (destino / f"{prefijo}.report.jsonl").write_text(
            "\n".join(x for x in lineas if json.loads(x)["entry_type"] != "completion") + "\n", encoding="utf-8")
        print("detector load failed: detectors.toxicity.ToxicCommentModel, skipping >>", flush=True)
        time.sleep(300)
        return 0
    (destino / f"{prefijo}.report.jsonl").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    if HITLOG.exists():
        (destino / f"{prefijo}.hitlog.jsonl").write_text(HITLOG.read_text(encoding="utf-8"), encoding="utf-8")
    print("dan.DanInTheWild   mitigation.MitigationBypass: FAIL  ok: 6/24")
    return 0


def argument_spec(argv):
    return argumento(argv, "--spec")


if __name__ == "__main__":
    sys.exit(main())
