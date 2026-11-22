"""DeepTeam falso para las pruebas herméticas de H5 (motor `deepteam`). Hace de las dos cosas que MRRobotIA lanza: el
ejecutable `deepteam` (`--version`) y el ejecutor `datos/deepteam_runner.py` (`--info` y `ENTRADA SALIDA`). No usa red,
modelo ni DeepTeam: escribe resultados copiados de una captura real saneada (`fixtures/deepteam/`).

Modos (variable MRROBOTIA_FALSO_MODO): normal, timeout, sinjson, errorglobal, entornomalo.
MRROBOTIA_FALSO_JUEZ: «bueno» (por defecto: detecta las cuatro violaciones de la calibración) o «ciego» (aprueba el
volcado del system prompt).
MRROBOTIA_FALSO_INFO: JSON que sustituye al de `--info` (para probar Python no soportado, sentry-sdk que falta...).
MRROBOTIA_FALSO_REGISTRO: fichero donde añade, por invocación, una línea JSON con los argumentos, la carpeta de
trabajo, las variables de entorno y la entrada recibida (para comprobar el bloqueo de red y por dónde viaja la clave).
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "deepteam"
RESULTADOS = FIXTURES / "quick_resultados_saneado.json"
VARIABLES = ("DEEPEVAL_TELEMETRY_OPT_OUT", "DEEPTEAM_TELEMETRY_OPT_OUT", "DEEPEVAL_DISABLE_DOTENV",
             "DEEPEVAL_DISABLE_LEGACY_KEYFILE", "DEEPEVAL_HOME", "DEEPEVAL_CACHE_FOLDER", "DEEPEVAL_RESULTS_FOLDER",
             "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "grpc_proxy", "HOME",
             "USERPROFILE", "TMP", "TEMP", "MRROBOTIA_API_KEY", "MIKLAVE", "MRROBOTIA_HOSTS_PERMITIDOS", "HF_HUB_OFFLINE",
             "CONFIDENT_API_KEY", "OPENAI_API_KEY", "ERROR_REPORTING", "OTEL_EXPORTER_OTLP_ENDPOINT", "PYTHONPATH")
INFO = {"python": "3.12.16", "deepteam": "1.0.10", "deepeval": "4.3.4", "sentry_sdk": "2.75.0", "importa": True,
        "error": None, "guardia": {"bloqueados": [], "proxy_muerto": 0}}


def registrar(argv, entrada=None):
    registro = os.environ.get("MRROBOTIA_FALSO_REGISTRO")
    if not registro:
        return
    with open(registro, "a", encoding="utf-8") as f:
        f.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "entrada": entrada,
                            "env": {k: os.environ.get(k) for k in VARIABLES}, "nombres": sorted(os.environ)}) + "\n")


def calibracion(casos):
    ciego = os.environ.get("MRROBOTIA_FALSO_JUEZ", "bueno") == "ciego"
    salida = []
    for c in casos:
        score = 0 if c["viola"] else 1
        if ciego and c["id"] == 1:
            score = 1                  # el juez aprueba el volcado del system prompt
        salida.append({"id": c["id"], "viola": c["viola"], "score": score, "error": None})
    return salida


def main():
    argv = sys.argv[1:]
    modo = os.environ.get("MRROBOTIA_FALSO_MODO", "normal")
    if argv == ["--version"]:
        registrar(argv)
        print("deepteam version " + os.environ.get("MRROBOTIA_FALSO_VERSION", "1.0.10"))
        return 0
    if argv == ["--info"]:
        registrar(argv)
        info = json.loads(os.environ.get("MRROBOTIA_FALSO_INFO") or json.dumps(INFO))
        print(json.dumps(info))
        return 0 if info.get("importa") else 4
    # ejecución: el módulo lanza `python -I -X utf8 runner ENTRADA SALIDA`, así que aquí argv = [ENTRADA, SALIDA]
    entrada_ruta, salida_ruta = argv[-2], argv[-1]
    entrada = Path(entrada_ruta).read_text(encoding="utf-8")
    registrar(argv, entrada)
    if modo == "entornomalo":
        print("deepteam_runner: el entorno no tiene el bloqueo de red completo: falso", file=sys.stderr)
        return 3
    if modo == "timeout":
        hijo = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        registro = os.environ.get("MRROBOTIA_FALSO_REGISTRO")
        if registro:
            Path(registro + ".hijo").write_text(str(hijo.pid), encoding="utf-8")
        print("[deepteam] pase 1/1", flush=True)
        time.sleep(300)
        return 0
    if modo == "sinjson":
        print("Error: invalid judge response: unknown key", file=sys.stderr)
        return 1
    datos = json.loads(RESULTADOS.read_text(encoding="utf-8"))
    pedido = json.loads(entrada)
    datos["calibracion"] = calibracion(pedido["calibracion"]) if pedido.get("calibracion") else None
    if modo == "errorglobal":
        datos["errores_globales"] = ["pase 2: ValueError: el juez no devuelve JSON válido"]
    fuente = os.environ.get("MRROBOTIA_FALSO_SALIDA")
    if fuente:
        datos = json.loads(Path(fuente).read_text(encoding="utf-8"))
    Path(salida_ruta).write_text(json.dumps(datos), encoding="utf-8")
    print("[deepteam] consulta 1 al sujeto (0.1 s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
