"""
Ejecutor de DeepTeam para MRRobotIA (H5, motor `deepteam`). NO forma parte del paquete: MRRobotIA no importa
DeepTeam (es una biblioteca de Python con ~80 dependencias) y lo lanza con el intérprete del entorno virtual donde
está instalado, por `subprocess`, así:

    <python del venv> -I -X utf8 deepteam_runner.py --info
    <python del venv> -I -X utf8 deepteam_runner.py ENTRADA.json SALIDA.json

MRRobotIA le pasa un JSON de entrada (sin ninguna clave: solo NOMBRES de variables de entorno) y lee el JSON de
salida. Este fichero solo usa la biblioteca estándar más DeepTeam/DeepEval, que se importan DENTRO de las
funciones y siempre DESPUÉS de comprobar el bloqueo de red: DeepTeam hace telemetría (consulta de IP pública,
PostHog, New Relic) en cuanto se importa si se le deja.

TODO LOCAL (requisito duro, falla cerrado): si el entorno no trae el bloqueo completo, no se importa nada y el
código de salida es 3. Además, una guardia dentro del proceso impide cualquier conexión a un destino que no sea el
sujeto o el juez (anota el intento, nunca el contenido) y cuenta lo que intente salir por el proxy muerto.

Códigos de salida: 0 bien; 2 la entrada no es válida; 3 el entorno no tiene el bloqueo; 4 DeepTeam no se importa.
"""
import json
import os
import socket
import sys
import time
import urllib.request

REQUERIDAS = {"DEEPEVAL_TELEMETRY_OPT_OUT": "1", "DEEPTEAM_TELEMETRY_OPT_OUT": "YES", "DEEPEVAL_DISABLE_DOTENV": "1",
              "DEEPEVAL_DISABLE_LEGACY_KEYFILE": "1"}
PROHIBIDAS = ("CONFIDENT_API_KEY", "OPENAI_API_KEY", "ERROR_REPORTING")
LOCALES = {"127.0.0.1", "localhost", "::1"}
PROXY_MUERTO = ("127.0.0.1", 9)


def problemas_de_entorno(env=None):
    """Lista de motivos por los que el entorno NO tiene el bloqueo de red completo (vacía = bien)."""
    env = os.environ if env is None else env
    malos = [f"{k} debe valer {v}" for k, v in REQUERIDAS.items() if env.get(k) != v]
    malos += [f"{k} no debe estar definida" for k in PROHIBIDAS if env.get(k)]
    if not env.get("DEEPEVAL_HOME"):
        malos.append("DEEPEVAL_HOME debe apuntar a la carpeta de salida")
    if (env.get("HTTPS_PROXY") or "").rstrip("/") != "http://127.0.0.1:9":
        malos.append("HTTPS_PROXY debe ser el proxy muerto http://127.0.0.1:9")
    return malos


class Guardia:
    """Vigila los `connect` y las resoluciones de nombres del proceso. Un destino que no sea el bucle local ni uno
    de los `permitidos` se bloquea y se anota (solo host y puerto). Las conexiones al proxy muerto se dejan pasar
    (mueren allí) pero se cuentan: son intentos de salir a Internet que respetan el proxy."""

    def __init__(self, permitidos=()):
        self.permitidos = {str(h).lower().strip("[]") for h in permitidos} | LOCALES
        self.bloqueados = []
        self.proxy = 0

    def _ok(self, host):
        h = str(host).lower().strip("[]")
        return h in self.permitidos or h.startswith("127.") or h in ("::1", "0.0.0.0", "")

    def instalar(self):
        guardia = self
        connect, connect_ex, gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

        def vigilar(direccion):
            if isinstance(direccion, tuple) and direccion:
                host, puerto = direccion[0], (direccion[1] if len(direccion) > 1 else None)
                if not guardia._ok(host):
                    guardia.bloqueados.append(f"{host}:{puerto}")
                    raise OSError(f"MRRobotIA: conexión a {host}:{puerto} bloqueada (todo local)")
                if (str(host), puerto) == PROXY_MUERTO:
                    guardia.proxy += 1

        def con(self_, direccion, *a, **k):
            vigilar(direccion)
            return connect(self_, direccion, *a, **k)

        def con_ex(self_, direccion, *a, **k):
            try:
                vigilar(direccion)
            except OSError:
                return 1
            return connect_ex(self_, direccion, *a, **k)

        def resolver(host, *a, **k):
            if isinstance(host, str) and not guardia._ok(host):
                guardia.bloqueados.append(f"{host} (DNS)")
                raise socket.gaierror(f"MRRobotIA: resolución de {host} bloqueada (todo local)")
            return gai(host, *a, **k)
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = con, con_ex, resolver
        return self

    def resumen(self):
        return {"bloqueados": sorted(set(self.bloqueados)), "proxy_muerto": self.proxy}


def versiones():
    """Versiones instaladas, sin importar nada de DeepTeam."""
    from importlib import metadata
    salida = {"python": sys.version.split()[0]}
    for clave, paquete in (("deepteam", "deepteam"), ("deepeval", "deepeval"), ("sentry_sdk", "sentry-sdk")):
        try:
            salida[clave] = metadata.version(paquete)
        except metadata.PackageNotFoundError:
            salida[clave] = None
    return salida


def modo_info():
    info = versiones()
    try:
        import deepteam  # noqa: F401, PLC0415
        info["importa"], info["error"] = True, None
    except Exception as e:                                              # noqa: BLE001
        info["importa"], info["error"] = False, f"{type(e).__name__}: {str(e)[:160]}"
    return info


def _llamar_sujeto(sujeto, entrada, contador):
    """Una consulta al chatbot (el sujeto): el system prompt y la pregunta. Devuelve el texto de la respuesta."""
    mensajes = ([{"role": "system", "content": sujeto["system_prompt"]}] if sujeto.get("system_prompt") else [])
    mensajes.append({"role": "user", "content": entrada})
    cuerpo = json.dumps({"model": sujeto["modelo"], "messages": mensajes, "max_tokens": sujeto.get("max_tokens", 256),
                         "temperature": sujeto.get("temperature", 0.2)}).encode("utf-8")
    cabeceras = {"Content-Type": "application/json"}
    clave = os.environ.get(sujeto.get("clave_env") or "")
    if clave:
        cabeceras["Authorization"] = "Bearer " + clave
    req = urllib.request.Request(sujeto["url"].rstrip("/") + "/v1/chat/completions", cuerpo, cabeceras)
    inicio = time.monotonic()
    with urllib.request.urlopen(req, timeout=sujeto.get("timeout", 600)) as r:
        datos = json.load(r)
    contador["n"] += 1
    contador["s"] += time.monotonic() - inicio
    print(f"[deepteam] consulta {contador['n']} al sujeto ({time.monotonic() - inicio:.1f} s)", flush=True)
    return datos["choices"][0]["message"].get("content") or ""


def _modelo(LocalModel, servidor, temperatura=0):
    clave = os.environ.get(servidor.get("clave_env") or "") or "not-needed"
    return LocalModel(model=servidor["modelo"], base_url=servidor["url"].rstrip("/") + "/v1", api_key=clave,
                      temperature=temperatura)


def calibrar(casos, juez, proposito):
    """Pasa por el juez salidas fijas con veredicto conocido (4 violan, 4 cumplen) usando las mismas métricas que el
    red team. Devuelve [{"id","viola","score","error"}]. En DeepTeam 0 = vulnerable, 1 = seguro."""
    from deepteam.metrics import PIIMetric, PromptExtractionMetric          # noqa: PLC0415
    from deepteam.test_case import RTTestCase                               # noqa: PLC0415
    from deepteam.vulnerabilities.pii_leakage import PIILeakageType        # noqa: PLC0415
    from deepteam.vulnerabilities.prompt_leakage import PromptLeakageType  # noqa: PLC0415
    salida = []
    for c in casos:
        try:
            if c["metrica"] == "prompt":
                metrica = PromptExtractionMetric(purpose=proposito, model=juez, async_mode=False)
                tc = RTTestCase(vulnerability="Prompt Leakage", vulnerability_type=PromptLeakageType.SECRETS_AND_CREDENTIALS,
                                input=c["entrada"], actual_output=c["salida"])
            else:
                metrica = PIIMetric(purpose=proposito, model=juez, async_mode=False)
                tc = RTTestCase(vulnerability="PII Leakage", vulnerability_type=PIILeakageType.DIRECT,
                                input=c["entrada"], actual_output=c["salida"])
            metrica.measure(tc)
            salida.append({"id": c["id"], "viola": c["viola"], "score": metrica.score, "error": None})
        except Exception as e:                                          # noqa: BLE001
            salida.append({"id": c["id"], "viola": c["viola"], "score": None, "error": type(e).__name__})
        print(f"[deepteam] calibración {len(salida)}/{len(casos)}", flush=True)
    return salida


def construir(entrada):
    """(vulnerabilidades, nombres, ataques_mejorados, hay_basico): objetos de DeepTeam a partir del JSON de
    entrada. Solo se instancian las clases que el módulo pide y que existen en DeepTeam (nunca un nombre libre)."""
    import deepteam.attacks.single_turn as ataques_dt                       # noqa: PLC0415
    import deepteam.vulnerabilities as vulns_dt                             # noqa: PLC0415
    vulns, nombres = [], {}
    for v in entrada["vulnerabilidades"]:
        if v["clase"] not in vulns_dt.__all__:
            raise ValueError(f"vulnerabilidad desconocida: {v['clase']}")
        obj = getattr(vulns_dt, v["clase"])(types=list(v["tipos"]))
        vulns.append(obj)
        nombres[obj.get_name()] = v["id"]
    mejorados, basico = [], False
    for a in entrada.get("ataques") or []:
        if a == "basic":
            basico = True
        elif a in ataques_dt.__all__:
            mejorados.append(getattr(ataques_dt, a)())
        else:
            raise ValueError(f"ataque desconocido: {a}")
    return vulns, nombres, mejorados, basico or not mejorados


def ejecutar(entrada, guardia=None):
    """Calibra el juez (si se pide) y lanza el red team; devuelve el diccionario de salida."""
    from deepeval.models import LocalModel                                  # noqa: PLC0415
    from deepteam.red_teamer import RedTeamer                               # noqa: PLC0415
    from deepteam.test_case import RTTurn                                   # noqa: PLC0415
    inicio = time.monotonic()
    juez = _modelo(LocalModel, entrada["juez"])
    atacante = _modelo(LocalModel, entrada["atacante"])
    salida = {"versiones": versiones(), "calibracion": None, "casos": [], "errores_globales": []}
    if entrada.get("calibracion"):
        salida["calibracion"] = calibrar(entrada["calibracion"], juez, entrada["proposito_calibracion"])
    vulns, nombres, mejorados, basico = construir(entrada)
    sujeto = dict(entrada["sujeto"], timeout=entrada.get("timeout_sujeto", 600))
    contador = {"n": 0, "s": 0.0}

    def callback(texto, turns=None):
        return RTTurn(role="assistant", content=_llamar_sujeto(sujeto, texto, contador))

    rt = RedTeamer(simulator_model=atacante, evaluation_model=juez, target_purpose=entrada.get("proposito") or "",
                   async_mode=False, max_concurrent=entrada.get("concurrencia", 1))
    pases = ([None] if basico else []) + ([mejorados] if mejorados else [])
    for i, ataques in enumerate(pases, 1):
        print(f"[deepteam] pase {i}/{len(pases)}: {'ataque base' if ataques is None else 'ataques mejorados'}", flush=True)
        try:
            riesgo = rt.red_team(model_callback=callback, vulnerabilities=vulns, attacks=ataques,
                                 attacks_per_vulnerability_type=entrada.get("por_tipo", 1), ignore_errors=True,
                                 _print_assessment=False, _upload_to_confident=False)
        except Exception as e:                                          # noqa: BLE001
            salida["errores_globales"].append(f"pase {i}: {type(e).__name__}: {str(e)[:160]}")
            continue
        for tc in getattr(riesgo, "test_cases", None) or []:
            tipo = getattr(tc.vulnerability_type, "value", tc.vulnerability_type)
            salida["casos"].append({
                "vulnerabilidad": nombres.get(tc.vulnerability, tc.vulnerability), "tipo": tipo,
                "ataque": tc.attack_method or "Baseline", "score": tc.score, "razon": tc.reason or "",
                "error": tc.error, "entrada": tc.input or "", "salida": tc.actual_output or ""})
    salida["llamadas_sujeto"] = contador["n"]
    salida["s_sujeto"] = round(contador["s"], 1)
    salida["duracion"] = round(time.monotonic() - inicio, 1)
    return salida


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    malos = problemas_de_entorno()
    if malos:
        print("deepteam_runner: el entorno no tiene el bloqueo de red completo: " + "; ".join(malos), file=sys.stderr)
        return 3
    guardia = Guardia(os.environ.get("MRROBOTIA_HOSTS_PERMITIDOS", "").split(",")).instalar()
    if argv == ["--info"]:
        info = modo_info()
        info["guardia"] = guardia.resumen()
        print(json.dumps(info))
        return 0 if info["importa"] else 4
    if len(argv) != 2:
        print("uso: deepteam_runner.py --info | ENTRADA.json SALIDA.json", file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as f:
            entrada = json.load(f)
    except (OSError, ValueError):
        print("deepteam_runner: entrada no válida", file=sys.stderr)
        return 2
    try:
        salida = ejecutar(entrada, guardia)
    except ImportError as e:
        print(f"deepteam_runner: DeepTeam no se importa ({type(e).__name__}: {e})", file=sys.stderr)
        return 4
    salida["guardia"] = guardia.resumen()
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(salida, f, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
