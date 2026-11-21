"""promptfoo falso para las pruebas herméticas de H5: acepta las mismas órdenes que promptfoo 0.126
(`--version`, `eval`, `redteam generate`) y escribe resultados copiados de capturas reales saneadas
(`fixtures/promptfoo/`). No usa red, modelo ni Node.

Modos (variable PROMPTFOO_FALSO_MODO): normal, nodeantiguo, timeout, caida, sinjson, errores.
PROMPTFOO_FALSO_JUEZ: «ciego» (por defecto, como el 7B autoevaluado: aprueba el volcado del system prompt) o
«bueno» (detecta las cuatro violaciones de la calibración).
PROMPTFOO_FALSO_SALIDA: ruta de un JSON de resultados que sustituye al de la fixture en los `eval` normales.
PROMPTFOO_FALSO_REGISTRO: fichero donde añade, por invocación, una línea JSON con los argumentos, el contenido de
la configuración recibida (-c) y las variables de entorno (para comprobar el bloqueo de red y por dónde viaja
la clave).
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "promptfoo"
GATE = FIXTURES / "gate1_resultados_saneado.json"
REDTEAM_RESULTADOS = FIXTURES / "rt4_resultados_saneado.json"
REDTEAM_GENERADO = FIXTURES / "rt4_redteam_generado.yaml"
VARIABLES = ("PROMPTFOO_DISABLE_TELEMETRY", "PROMPTFOO_DISABLE_UPDATE", "PROMPTFOO_DISABLE_SHARING",
             "PROMPTFOO_DISABLE_REMOTE_GENERATION", "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION",
             "PROMPTFOO_FAILED_TEST_EXIT_CODE", "PROMPTFOO_CONFIG_DIR", "PROMPTFOO_LOG_DIR", "HTTPS_PROXY",
             "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "PROMPTFOO_EVAL_TIMEOUT_MS",
             "REQUEST_TIMEOUT_MS", "PROMPTFOO_MAX_EVAL_TIME_MS", "OPENAI_API_KEY", "OPENAI_BASE_URL",
             "MRROBOTIA_API_KEY", "MIKLAVE", "NO_COLOR", "PYTHONUTF8")
ANTIGUO = ("\x1b[33mpromptfoo requires a supported Node.js runtime.\n\nDetected: v22.20.0\nRequired: >=22.22.0\n\n"
           "Install a supported Node.js version and try again.\x1b[0m")


def argumento(argv, nombre):
    return argv[argv.index(nombre) + 1] if nombre in argv else None


def registrar(argv):
    registro = os.environ.get("PROMPTFOO_FALSO_REGISTRO")
    if not registro:
        return
    cfg = argumento(argv, "-c")
    texto = None
    if cfg and Path(cfg).is_file():
        texto = Path(cfg).read_text(encoding="utf-8", errors="replace")
    with open(registro, "a", encoding="utf-8") as f:
        f.write(json.dumps({"argv": argv, "config": texto, "cwd": os.getcwd(),
                            "env": {k: os.environ.get(k) for k in VARIABLES}}) + "\n")


def resultados_calibracion(config):
    """Veredictos del juez simulado para las pruebas de la calibración."""
    ciego = os.environ.get("PROMPTFOO_FALSO_JUEZ", "ciego") == "ciego"
    salida = []
    for i, t in enumerate(config["tests"]):
        esperado = (t.get("metadata") or {}).get("esperado")
        ok = esperado == "pasa"
        if ciego and "vuelca el system prompt" in t.get("description", ""):
            ok = True            # el juez del mismo modelo aprueba el volcado: es lo que se midió
        salida.append({"success": ok, "score": 1 if ok else 0, "failureReason": 0 if ok else 1, "testIdx": i,
                       "vars": t.get("vars"), "metadata": t.get("metadata"),
                       "response": {"output": (t.get("vars") or {}).get("salida", "")},
                       "gradingResult": {"pass": ok, "score": 1 if ok else 0, "reason": "falso",
                                         "componentResults": [{"pass": ok, "score": 1 if ok else 0, "reason": "falso",
                                                               "assertion": t["assert"][0]}]}})
    return salida


def escribir(ruta, resultados):
    Path(ruta).write_text(json.dumps({"evalId": "falso", "results": {"version": 3, "results": resultados}}),
                          encoding="utf-8")


def main():
    argv = sys.argv[1:]
    modo = os.environ.get("PROMPTFOO_FALSO_MODO", "normal")
    if "--version" in argv:
        registrar(argv)
        if modo == "nodeantiguo":
            print(ANTIGUO)
            return 1
        print(os.environ.get("PROMPTFOO_FALSO_VERSION", "0.126.0"))
        return 0
    registrar(argv)
    if modo == "nodeantiguo":
        print(ANTIGUO)
        return 1
    salida = argumento(argv, "-o")
    if modo == "timeout":
        hijo = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        registro = os.environ.get("PROMPTFOO_FALSO_REGISTRO")
        if registro:
            Path(registro + ".hijo").write_text(str(hijo.pid), encoding="utf-8")
        print("Running tests...", flush=True)
        time.sleep(300)
        return 0
    if argv[:2] == ["redteam", "generate"]:
        if modo == "caida" and os.environ.get("PROMPTFOO_FALSO_FALLA") == "generar":
            print("Error: Test case generation failed: connect ECONNREFUSED 127.0.0.1:8090")
            return 1
        Path(salida).write_text(REDTEAM_GENERADO.read_text(encoding="utf-8"), encoding="utf-8")
        print("Wrote 108 test cases")
        return 0
    if argv[:1] == ["eval"]:
        config = argumento(argv, "-c")
        if modo == "sinjson":
            print("Error: invalid config: unknown key")
            return 1
        if config.endswith(".yaml") and "redteam" in Path(config).name:
            if modo == "caida":
                print("Error: API call error: connect ECONNREFUSED 127.0.0.1:8090")
                return 100
            datos = json.loads(REDTEAM_RESULTADOS.read_text(encoding="utf-8"))["results"]["results"]
        else:
            cfg = json.loads(Path(config).read_text(encoding="utf-8"))
            if cfg.get("providers") == ["echo"]:
                escribir(salida, resultados_calibracion(cfg))
                return 0
            fuente = os.environ.get("PROMPTFOO_FALSO_SALIDA")
            datos = json.loads(Path(fuente or GATE).read_text(encoding="utf-8"))["results"]["results"]
        if modo == "errores":
            datos = [dict(d, success=False, failureReason=2, error="API call error: connect ECONNREFUSED",
                          response={"error": "API call error: connect ECONNREFUSED"}, gradingResult=None) for d in datos]
        escribir(salida, datos)
        print("Eval complete")
        return 0
    print("Error: unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main())
