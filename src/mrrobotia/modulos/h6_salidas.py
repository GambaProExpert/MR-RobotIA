"""
H6-SALIDAS — ¿salen datos de la red? (alias `Young_Elliot`).

Los demás módulos miran el modelo o la configuración; este mira la RED. Responde a dos preguntas sobre un servidor
llama.cpp o vLLM que corre en ESTA máquina:

1. Auditoría estática (pasiva, instantánea, entra en `all`): ¿qué canales por los que puede salir información están
   configurados? Telemetría, descargas al arrancar, hub de modelos en línea, RPC, MCP, herramientas, trazas OTLP,
   eventos y transferencia de la caché KV, proxies. Se lee solo la línea de órdenes saneada, el entorno del proceso
   (si se puede leer) y los ficheros de estado de vLLM.
2. Observación (solo con `-a` y `allow_active`, o con `-s egress` pedido a mano): se muestrea la tabla de sockets del
   sistema por PID durante una ventana y se anotan las conexiones del ÁRBOL de procesos del servidor que no son
   loopback, ni del propio equipo, ni de la lista blanca `egress.allow`. Con `-a` hay además una ventana con tráfico
   de CANARIO (peticiones con una marca única) y se correlacionan las peticiones con las conexiones nuevas.

No lanza, reinicia ni modifica nada. Solo biblioteca estándar. Es el ÚNICO dueño de los canales de salida: la
comprobación de telemetría de vLLM que estaba en H2-ARRANQUE vive aquí (`H6-SALIDAS-CANAL-TELEMETRIA`).

Límites (se repiten en el informe y la guía): con TLS se ve el destino, no el contenido; el muestreo puede perder
conexiones de menos de unos 100 ms; solo se ve el árbol del servidor y solo durante la ventana; no se ve el DNS; un
servidor dentro de WSL no se ve desde Windows (hay que ejecutar MRRobotIA dentro de WSL); en Windows el entorno de
otro proceso no se lee y la tabla UDP no da la dirección remota. Solo Windows y Linux leen procesos y sockets: en otro
sistema no se observa ni se envía canario (`H6-SALIDAS-SO-NO-SOPORTADO`), y si H2-ID no asoció el servidor a un proceso
los canales que dependen de su línea de órdenes o su entorno salen «sin comprobar» (aunque egress.pids permita observarlo).
Una ventana en la que no se vio el árbol no cuenta como limpia, y si el árbol deja de verse tras la ventana pasiva no se
envía canario.

PRIVACIDAD: el canario nunca se imprime ni se guarda; las URL de proxy y de MCP no se conservan (solo presencia).
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from mrrobotia import procesos, red
from mrrobotia.contexto import rotular
from mrrobotia.nucleo import Hallazgo, Modulo, Severidad
from mrrobotia.perfiles import perfil_de
from mrrobotia.perfiles.base import REFS_SUPPLY
from mrrobotia.perfiles.vllm import exclusion_telemetria

MODULO = "H6-SALIDAS"
REFS_SALIDA = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.4"}
REFS_TOOLS = {"owasp": "LLM06", "atlas": "AML.T0053", "nist": "2.9"}
TIPOS_SERVIDOR = ("llama.cpp", "vllm")

# clave -> (tipo, defecto, mínimo, máximo). Se puede cambiar en las pruebas (ventanas cortas).
LIMITES = {
    "passive_window": (int, 10, 0, 600),
    "active_window": (int, 30, 10, 1800),
    "trailing": (int, 10, 0, 600),
    "interval_ms": (int, 100, 50, 1000),
    "canaries": (int, 5, 1, 50),
    "max_tokens": (int, 8, 1, 64),
    "correlation_s": (float, 5.0, 0.5, 60.0),
}
CLAVES_EGRESS = set(LIMITES) | {"allow", "canary_endpoint", "api_key_env", "pids", "process_names", "history_files"}
ENDPOINTS_CANARIO = ("chat", "completion", "tokenize")
MAX_FILAS_MUESTRA = 10_000
MAX_CONEXIONES = 1_000
MAX_INICIOS = 200
# Destinos a los que vLLM hace `connect()` en un socket UDP solo para averiguar su IP (no envía paquetes).
FIJAS_GET_IP = {("8.8.8.8", 80), ("2001:4860:4860::8888", 80)}
_VALORES_VERDADEROS = {"1", "ON", "YES", "TRUE"}

# Variables que H6 lee del entorno del proceso. Las secretas (proxies: pueden llevar `user:pass@`) pasan a True.
VARIABLES_H6 = {
    "HF_HUB_OFFLINE": False, "TRANSFORMERS_OFFLINE": False, "HF_ENDPOINT": False, "VLLM_USAGE_STATS_SERVER": False,
    "VLLM_CONFIG_ROOT": False, "VLLM_USE_MODELSCOPE": False, "XDG_CONFIG_HOME": False, "HOME": False,
    "HTTPS_PROXY": True, "HTTP_PROXY": True, "ALL_PROXY": True, "https_proxy": True, "http_proxy": True,
    "all_proxy": True, "LLAMA_ARG_OFFLINE": False, "LLAMA_ARG_RPC": True, "LLAMA_ARG_MCP_SERVERS_CONFIG": True,
    "LLAMA_ARG_MCP_SERVERS_JSON": True, "LLAMA_ARG_UI_MCP_PROXY": False, "LLAMA_ARG_AGENT": False,
    "LLAMA_ARG_HF_REPO": False, "LLAMA_ARG_MODEL_URL": True, "LLAMA_ARG_MMPROJ_URL": True,
    "LLAMA_ARG_DOCKER_REPO": False, "LLAMA_ARG_TOOLS_RUNTIME": False, "VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS": False,
}
FRASE_LIMITES = ("No prueba que nunca salga nada: conexiones de menos de ~{ms} ms, procesos fuera del árbol, DNS y lo "
                 "que ocurra fuera de la ventana no se ven.")


# ---------------------------------------------------------------------------------------------- configuración
def validar_config(bloque):
    """(cfg, None) con los valores por defecto aplicados, o (None, motivo) si el bloque `egress` no es válido."""
    cfg = {c: v[1] for c, v in LIMITES.items()}
    cfg.update({"allow": [], "canary_endpoint": "chat", "api_key_env": "MRROBOTIA_API_KEY", "pids": [],
                "process_names": [], "history_files": True})
    if bloque is None:
        return cfg, None
    if not isinstance(bloque, dict):
        return None, "egress debe ser un objeto JSON"
    desconocidas = sorted(str(k) for k in bloque if k not in CLAVES_EGRESS)
    if desconocidas:
        return None, f"claves desconocidas en egress: {', '.join(desconocidas)}"
    for clave, (tipo, _, minimo, maximo) in LIMITES.items():
        if clave not in bloque:
            continue
        v = bloque[clave]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or (tipo is int and int(v) != v):
            return None, f"egress.{clave} debe ser un número{' entero' if tipo is int else ''}"
        if not minimo <= v <= maximo:
            return None, f"egress.{clave} debe estar entre {minimo} y {maximo}"
        cfg[clave] = tipo(v)
    for clave in ("allow", "process_names"):
        if clave in bloque:
            v = bloque[clave]
            if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
                return None, f"egress.{clave} debe ser una lista de cadenas no vacías"
            cfg[clave] = [x.strip() for x in v]
    if "pids" in bloque:
        v = bloque["pids"]
        if not isinstance(v, list) or not all(isinstance(x, int) and not isinstance(x, bool) and x > 0 for x in v):
            return None, "egress.pids debe ser una lista de enteros positivos"
        cfg["pids"] = list(v)
    if "canary_endpoint" in bloque:
        if bloque["canary_endpoint"] not in ENDPOINTS_CANARIO:
            return None, f"egress.canary_endpoint debe ser uno de: {', '.join(ENDPOINTS_CANARIO)}"
        cfg["canary_endpoint"] = bloque["canary_endpoint"]
    if "api_key_env" in bloque:
        v = bloque["api_key_env"]
        if not (isinstance(v, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v)):
            return None, "egress.api_key_env debe ser el NOMBRE de una variable de entorno (nunca la clave)"
        cfg["api_key_env"] = v
    if "history_files" in bloque:
        if not isinstance(bloque["history_files"], bool):
            return None, "egress.history_files debe ser true o false"
        cfg["history_files"] = bloque["history_files"]
    return cfg, None


def _ip(texto):
    try:
        ip = ipaddress.ip_address(str(texto).strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def parsear_permitidas(entradas, resolver=socket.getaddrinfo):
    """(reglas, nombres_resueltos, error). Una regla es (red, puerto|None). Admite `10.0.0.5`, `10.0.0.0/8`,
    `10.0.0.5:8092`, `[fd00::1]:50052` y un nombre, que se resuelve UNA vez (consulta DNS: se avisa en el informe)."""
    reglas, nombres = [], []
    for entrada in entradas or ():
        texto, puerto = entrada.strip(), None
        try:
            if texto.startswith("[") and "]:" in texto:
                texto, p = texto[1:].split("]:", 1)
                puerto = int(p)
            elif texto.count(":") == 1 and "/" not in texto:
                texto, p = texto.split(":", 1)
                puerto = int(p)
            if puerto is not None and not 0 < puerto <= 65535:
                return [], [], f"puerto no válido en egress.allow: {entrada}"
            try:
                reglas.append((ipaddress.ip_network(texto.strip("[]"), strict=False), puerto))
            except ValueError:
                try:
                    direcciones = {i[4][0] for i in resolver(texto, None)}
                except OSError:
                    return [], [], f"no se pudo interpretar ni resolver egress.allow: {texto}"
                for d in direcciones:
                    reglas.append((ipaddress.ip_network(d.split("%", 1)[0], strict=False), puerto))
                nombres.append(texto)
        except ValueError:
            return [], [], f"entrada no válida en egress.allow: {entrada}"
    return reglas, nombres, None


# ---------------------------------------------------------------------------------------------- clasificación
def es_privada(ip):
    return ip.is_private or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10")


def subclase_de(texto):
    ip = _ip(texto)
    return "privada" if ip is not None and es_privada(ip) else "publica"


def _es_local(ip, propias):
    return ip.is_loopback or str(ip) in propias


def _esta_permitida(ip, puerto, permitidas):
    return any(ip in red_ and (p is None or p == puerto) for red_, p in permitidas)


def clasificar(f, puertos_escucha, propias, permitidas, puerto_api):
    """Clase de una fila del árbol (función pura): escucha, entrante, pull, propia, permitida, SALIDA_DNS,
    SALIDA_UDP, SALIDA o ignorada (no atribuible: TIME_WAIT sin PID, o el `connect()` de vLLM para saber su IP)."""
    if f.estado in ("LISTEN", "UDP") or f.remota is None:
        return "escucha"
    ip = _ip(f.remota)
    if ip is None or ip.is_unspecified:
        return "escucha"
    if f.pid in (0, None) or f.estado == "TIME_WAIT":
        return "ignorada"
    if f.proto == "tcp" and f.puerto_local in puertos_escucha:
        if _es_local(ip, propias) or _esta_permitida(ip, f.puerto_remoto, permitidas) or f.puerto_local == puerto_api:
            return "entrante"
        return "pull"
    if _es_local(ip, propias):
        return "propia"
    if _esta_permitida(ip, f.puerto_remoto, permitidas):
        return "permitida"
    if f.proto == "udp":
        if f.puerto_remoto == 53:
            return "SALIDA_DNS"
        if (str(ip), f.puerto_remoto) in FIJAS_GET_IP:
            return "ignorada"
        return "SALIDA_UDP"
    return "SALIDA"


# ---------------------------------------------------------------------------------------------- observación
@dataclass
class Observacion:
    muestras: int = 0
    segundos: float = 0.0
    coste_ms: float = 0.0
    pids: dict = field(default_factory=dict)         # pid -> nombre del proceso del árbol
    conexiones: list = field(default_factory=list)   # SALIDA*, pull: ver `observar`
    clases: dict = field(default_factory=dict)       # clase -> filas vistas (recuento de todas las muestras)
    sin_permiso: bool = False                        # Linux: algún fd del árbol no se pudo leer
    truncada: bool = False                           # se superó un tope de filas o de conexiones
    puertos_escucha: list = field(default_factory=list)
    ventana: str = ""


def _leer_sockets_defecto(pids):
    if os.name == "nt":
        return red.sockets_windows(), False
    return red.sockets_linux(pids)


def observar(raices, segundos, intervalo, *, nombres=(), permitidas=(), propias_extra=(), puerto_api=None,
             parar=None, reloj=time.monotonic, dormir=time.sleep, leer_procesos=None, leer_sockets=None, t0=None,
             ventana=""):
    """Muestrea durante `segundos` (al menos una vez) las conexiones del árbol de procesos de `raices` (PID) o de los
    procesos cuyo nombre esté en `nombres`. El árbol se recalcula en cada muestra (vLLM crea sus hijos después de
    arrancar). `leer_procesos() -> {pid: (ppid, nombre)}` y `leer_sockets(pids) -> (filas, sin_permiso)` son
    inyectables. Los tiempos son relativos a `t0` (reloj común con el envío del canario)."""
    leer_procesos = leer_procesos or procesos.tabla_pid_ppid
    leer_sockets = leer_sockets or _leer_sockets_defecto
    t0 = reloj() if t0 is None else t0
    inicio = reloj()
    obs = Observacion(ventana=ventana)
    por_clave, escucha, tiempos = {}, set(), []
    nombres = {n.lower() for n in nombres}
    while True:
        a = time.perf_counter()
        tabla = leer_procesos()
        todas = set(raices) | {p for p, (_, n) in tabla.items() if n.lower() in nombres}
        pids = procesos.arbol_de(tabla, todas)
        ahora = reloj() - t0
        if pids:
            filas, sin_permiso = leer_sockets(pids)
            obs.sin_permiso = obs.sin_permiso or sin_permiso
            if len(filas) > MAX_FILAS_MUESTRA * 20:
                filas, obs.truncada = filas[:MAX_FILAS_MUESTRA * 20], True
            propias = {f.local for f in filas} | set(propias_extra)
            propias = {str(_ip(p)) for p in propias if _ip(p) is not None and not _ip(p).is_unspecified}
            del_arbol = [f for f in filas if f.pid in pids]
            if len(del_arbol) > MAX_FILAS_MUESTRA:
                del_arbol, obs.truncada = del_arbol[:MAX_FILAS_MUESTRA], True
            escucha |= {f.puerto_local for f in del_arbol if f.estado == "LISTEN"}
            for pid in pids:
                obs.pids[pid] = tabla[pid][1]
            for f in del_arbol:
                clase = clasificar(f, escucha, propias, permitidas, puerto_api)
                obs.clases[clase] = obs.clases.get(clase, 0) + 1
                if not (clase.startswith("SALIDA") or clase == "pull"):
                    continue
                puerto = f.puerto_local if clase == "pull" else f.puerto_remoto
                clave = (clase, f.proto, f.pid, f.remota, puerto)
                c = por_clave.get(clave)
                if c is None:
                    if len(por_clave) >= MAX_CONEXIONES:
                        obs.truncada = True
                        continue
                    c = por_clave[clave] = {
                        "clase": clase, "subclase": subclase_de(f.remota), "proto": f.proto, "pid": f.pid,
                        "proceso": tabla[f.pid][1] if f.pid in tabla else "?", "remota": f.remota, "puerto": puerto,
                        "estados": set(), "primera_s": round(ahora, 3), "ultima_s": round(ahora, 3),
                        "puertos_locales": set(), "inicios": [], "ventana": ventana}
                c["estados"].add(f.estado)
                c["ultima_s"] = round(ahora, 3)
                if f.puerto_local not in c["puertos_locales"]:
                    c["puertos_locales"].add(f.puerto_local)
                    if len(c["inicios"]) < MAX_INICIOS:
                        c["inicios"].append(round(ahora, 3))
        obs.muestras += 1
        tiempos.append(time.perf_counter() - a)
        if (parar is not None and parar.is_set()) or reloj() - inicio >= segundos:
            break
        dormir(max(0.0, intervalo - (time.perf_counter() - a)))
    obs.segundos = round(reloj() - inicio, 2)
    obs.coste_ms = round(1000 * sum(tiempos) / len(tiempos), 2) if tiempos else 0.0
    obs.puertos_escucha = sorted(escucha)
    obs.conexiones = [{**c, "estados": sorted(c["estados"]), "n": len(c["puertos_locales"])}
                      for c in por_clave.values()]
    for c in obs.conexiones:
        del c["puertos_locales"]
    return obs


# ---------------------------------------------------------------------------------------------- síntesis
def _ventanas(c):
    return "+".join(sorted(c["ventanas"]))


def _unir_destinos(*observaciones):
    """Une las conexiones de las ventanas por destino (clase, proto, IP, puerto)."""
    destinos = {}
    for obs in observaciones:
        if obs is None:
            continue
        for c in obs.conexiones:
            d = destinos.setdefault((c["clase"], c["proto"], c["remota"], c["puerto"]), {
                "clase": c["clase"], "subclase": c["subclase"], "proto": c["proto"], "remota": c["remota"],
                "puerto": c["puerto"], "pids": {}, "estados": set(), "n": 0, "primera_s": c["primera_s"],
                "ventanas": set(), "inicios": {}, "por_ventana": {}})
            d["pids"][c["pid"]] = c["proceso"]
            d["estados"].update(c["estados"])
            d["n"] += c["n"]
            d["primera_s"] = min(d["primera_s"], c["primera_s"])
            d["ventanas"].add(c["ventana"])
            d["inicios"].setdefault(c["ventana"], []).extend(c["inicios"])
    return list(destinos.values())


def _fmt_s(x):
    return f"{x:.1f}".replace(".", ",")


def _correlacion(destino, envios, correlacion_s):
    """Peticiones (índices) tras las que apareció una conexión NUEVA a este destino en la ventana activa, y el
    retraso de la primera. Solo cuenta la ventana activa."""
    inicios = destino["inicios"].get("activa", [])
    golpes, retraso = set(), None
    for i, (te, _) in enumerate(envios):
        siguientes = [t - te for t in inicios if te <= t <= te + correlacion_s]
        if siguientes:
            golpes.add(i)
            if retraso is None:
                retraso = (i + 1, min(siguientes))
    return golpes, retraso


def hallazgos_desde_observacion(pasiva, activa, envios, meta):
    """Hallazgos de las ventanas (función pura). `envios` = [(t_envio_s, ok)] en el mismo reloj que las
    observaciones. `meta`: intervalo_ms, correlacion_s, puertos_internos y los datos del resumen. Devuelve
    (hallazgos, conexiones_para_el_informe, hay_salidas). El canario nunca llega aquí."""
    intervalo = meta["intervalo_ms"]
    destinos = _unir_destinos(pasiva, activa)
    vistos_en_pasiva = {(c["clase"], c["proto"], c["remota"], c["puerto"]) for c in (pasiva.conexiones if pasiva else [])}
    hallazgos, filas_informe = [], []
    # Correlación: solo conexiones TCP nuevas (no vistas en reposo) tras las peticiones.
    grupos = {"publica": set(), "privada": set()}
    resultados = {}
    for d in destinos:
        k = (d["clase"], d["proto"], d["remota"], d["puerto"])
        if d["clase"] != "SALIDA" or not envios or k in vistos_en_pasiva or "activa" not in d["ventanas"]:
            continue
        golpes, retraso = _correlacion(d, envios, meta["correlacion_s"])
        resultados[k] = (golpes, retraso)
        grupos[d["subclase"]] |= golpes
    minimo = max(2, math.ceil(0.5 * len(envios))) if envios else 0
    correlada = {g: len(h) >= minimo and bool(envios) for g, h in grupos.items()}
    n = 0
    for d in sorted(destinos, key=lambda x: (x["clase"], x["primera_s"])):
        k = (d["clase"], d["proto"], d["remota"], d["puerto"])
        pid_txt = ", ".join(f"PID {p} ({nom})" for p, nom in sorted(d["pids"].items()))
        if d["clase"] == "pull":
            interno = d["puerto"] in meta.get("puertos_internos", {})
            sev = Severidad.ALTA if interno else Severidad.MEDIA
            que = f" ({meta['puertos_internos'][d['puerto']]})" if interno else ""
            hallazgos.append(Hallazgo(
                MODULO, f"H6-SALIDAS-PULL-{d['puerto']}", "Un equipo externo está conectado a un puerto interno del servidor",
                sev, "potencial",
                f"tcp desde {d['remota']} al puerto {d['puerto']}{que} · {pid_txt} · {', '.join(sorted(d['estados']))} · "
                f"primera a {_fmt_s(d['primera_s'])} s ({_ventanas(d)}) · {d['n']} conexión(es); no es el puerto de la API",
                "Cierra ese puerto o enlázalo a loopback: un suscriptor externo puede llevarse datos derivados de los "
                "prompts (eventos KV, RPC, coordinación).", REFS_SALIDA,
                {"seccion": "egress", "tipo": "conexion", "destino": f"{d['remota']}:{d['puerto']}", "clase": "pull"}))
            filas_informe.append(_fila_informe(d, "pull", pid_txt))
            continue
        n += 1
        base = (f"{d['proto']} {d['remota']}:{d['puerto']} · {pid_txt} · {', '.join(sorted(d['estados']))} · "
                f"primera a {_fmt_s(d['primera_s'])} s ({_ventanas(d)}")
        golpes, retraso = resultados.get(k, (set(), None))
        provocada = d["clase"] == "SALIDA" and bool(golpes) and correlada[d["subclase"]]
        if provocada and retraso:
            base += f", {_fmt_s(retraso[1])} s tras la petición {retraso[0]}"
        evidencia = base + f") · {d['n']} conexión(es)"
        if d["clase"] == "SALIDA_DNS":
            hallazgos.append(Hallazgo(
                MODULO, "H6-SALIDAS-DNS", "El servidor consulta un servidor DNS directamente", Severidad.BAJA, "potencial",
                evidencia, "Comprueba qué nombres resuelve y por qué: una consulta DNS ya revela el nombre.", REFS_SALIDA,
                {"seccion": "egress", "tipo": "conexion", "destino": f"{d['remota']}:{d['puerto']}", "clase": "dns"}))
        elif d["clase"] == "SALIDA_UDP":
            hallazgos.append(Hallazgo(
                MODULO, f"H6-SALIDAS-UDP-{n}", "Socket UDP conectado a un destino no permitido", Severidad.MEDIA, "potencial",
                evidencia, "Identifica el proceso y el destino; bloquea la salida del host salvo los destinos declarados "
                "en egress.allow.", REFS_SALIDA,
                {"seccion": "egress", "tipo": "conexion", "destino": f"{d['remota']}:{d['puerto']}", "clase": "udp"}))
        else:
            publica = d["subclase"] == "publica"
            sev = Severidad.ALTA if (publica or provocada) else Severidad.MEDIA
            clase_txt = "pública" if publica else "de la red local"
            hallazgos.append(Hallazgo(
                MODULO, f"H6-SALIDAS-CONEXION-{n}", f"El servidor abre conexiones salientes {clase_txt}", sev, "confirmado",
                evidencia, "Identifica el proceso y el destino; si es telemetría, desactívala (ver los canales); bloquea "
                "la salida del host con el cortafuegos salvo destinos declarados en egress.allow.", REFS_SALIDA,
                {"seccion": "egress", "tipo": "conexion", "destino": f"{d['remota']}:{d['puerto']}",
                 "clase": d["subclase"], "provocada": provocada}))
        filas_informe.append(_fila_informe(d, d["subclase"] if d["clase"] == "SALIDA" else d["clase"], pid_txt))
    if correlada["publica"]:
        hallazgos.append(Hallazgo(
            MODULO, "H6-SALIDAS-CORRELACION", "Las peticiones provocan conexiones salientes a internet", Severidad.CRITICA,
            "confirmado",
            f"aparecieron conexiones nuevas a destinos públicos tras {len(grupos['publica'])} de {len(envios)} peticiones "
            f"con canario (ventana de {meta['correlacion_s']:g} s), y no se veían en reposo: el contenido de los prompts o de "
            "las respuestas puede estar saliendo (con TLS se ve el destino, no el contenido)",
            "Revisa las trazas, el registro remoto, el MCP y las herramientas del servidor y de la pasarela de delante; "
            "bloquea la salida del host salvo lo declarado en egress.allow.", REFS_SALIDA,
            {"seccion": "egress", "tipo": "correlacion", "peticiones": len(envios), "con_salida": len(grupos["publica"])}))
    hay_salidas = any(d["clase"] in ("SALIDA", "SALIDA_UDP", "SALIDA_DNS") for d in destinos)
    if (pasiva is not None and pasiva.sin_permiso) or (activa is not None and activa.sin_permiso):
        hallazgos.append(Hallazgo(
            MODULO, "H6-SALIDAS-SIN-PERMISO", "No se pudieron leer los descriptores de algún proceso del servidor",
            Severidad.INFO, "sin_concluir", "algún /proc/<pid>/fd del árbol no es legible (otro usuario o contenedor)",
            "Ejecuta MRRobotIA con el usuario del servidor o con root: sin eso, sus conexiones no se atribuyen.",
            REFS_SALIDA))
    return hallazgos, filas_informe, hay_salidas


SUFIJO_ESTATICA = ("; la auditoría estática se queda en lo declarado y los canales que dependen del proceso (descargas, "
                   "RPC, MCP, trazas, eventos KV, proxies) figuran «sin comprobar» si no se leyó su línea de órdenes ni "
                   "su entorno")


def _fila_informe(d, clase, pid_txt):
    return {"destino": f"{d['remota']}:{d['puerto']}", "clase": clase, "proceso": pid_txt,
            "ventana": _ventanas(d), "estados": ", ".join(sorted(d["estados"])), "n": d["n"],
            "primera_s": d["primera_s"]}


def frase_ventana_limpia(segundos, intervalo_ms):
    return (f"Sin salidas del árbol del servidor durante {segundos:g} s (muestreo cada {intervalo_ms} ms). "
            + FRASE_LIMITES.format(ms=intervalo_ms))


# ---------------------------------------------------------------------------------------------- auditoría estática
def _verdadero(valor):
    return valor is True or str(valor).strip().upper() in _VALORES_VERDADEROS


def _host_de(url):
    try:
        return urllib.parse.urlsplit(url if "://" in str(url) else "//" + str(url)).hostname or ""
    except ValueError:
        return ""


def _es_host_local(host):
    return not host or red.clasificar_direccion(host) == "loopback" or str(host).lower() == "localhost"


def entorno_de(servidor):
    """(entorno, legible): el que dejó H2-ID más las variables propias de H6, leídas del proceso. Los valores no
    secretos se usan solo aquí: nunca llegan al informe."""
    env = dict(servidor.entorno)
    if servidor.pid is not None:
        env.update(procesos.leer_entorno(servidor.pid, VARIABLES_H6))
        legible = bool(env) or procesos.entorno_legible(servidor.pid)
    else:
        legible = bool(env)
    return env, legible


def raiz_config_vllm(env):
    """Carpeta de estado de vLLM: `$VLLM_CONFIG_ROOT`, `$XDG_CONFIG_HOME/vllm` o `~/.config/vllm`."""
    if isinstance(env.get("VLLM_CONFIG_ROOT"), str) and env["VLLM_CONFIG_ROOT"]:
        return Path(env["VLLM_CONFIG_ROOT"])
    if isinstance(env.get("XDG_CONFIG_HOME"), str) and env["XDG_CONFIG_HOME"]:
        return Path(env["XDG_CONFIG_HOME"]) / "vllm"
    home = env.get("HOME") if isinstance(env.get("HOME"), str) and env.get("HOME") else str(Path.home())
    return Path(home) / ".config" / "vllm"


class _Canales:
    """Recoge los hallazgos de los canales y la tabla de canales (abiertos, cerrados y sin comprobar)."""

    def __init__(self):
        self.hallazgos, self.tabla = [], []

    def abierto(self, canal, titulo, sev, evidencia, recomendacion, refs=REFS_SALIDA, estado="confirmado"):
        sin_comprobar = estado == "sin_concluir"
        self.hallazgos.append(Hallazgo(
            MODULO, f"H6-SALIDAS-CANAL-{canal}", titulo, sev, estado, evidencia, recomendacion, refs,
            {"seccion": "egress", "tipo": "canal", "canal": canal}))
        self.tabla.append({"canal": canal, "estado": "sin comprobar" if sin_comprobar else
                           ("abierto" if estado == "confirmado" else "posible"),
                           "evidencia": evidencia, "severidad": sev.name})

    def cerrado(self, canal, evidencia):
        self.tabla.append({"canal": canal, "estado": "cerrado", "evidencia": evidencia, "severidad": "-"})

    def sin_comprobar(self, canal, evidencia):
        """Solo la tabla, sin hallazgo propio: la evidencia de la fila dice el motivo."""
        self.tabla.append({"canal": canal, "estado": "sin comprobar", "evidencia": evidencia, "severidad": "-"})


# Canales que solo se ven con la línea de órdenes o el entorno del proceso (la telemetría de vLLM ya se trata aparte).
CANALES_DEL_PROCESO = {
    "llama.cpp": ("DESCARGA", "RPC", "MCP", "PROXY-UI", "PROXY"),
    "vllm": ("HUB", "CARGA-REMOTA", "TRAZAS", "KV-EVENTOS", "KV-TRANSFER", "MCP", "PROXY"),
}
MOTIVO_SIN_PROCESO = ("H2-ID no asoció el servidor a ningún proceso (egress.pids y egress.process_names solo sirven para "
                      "observar): sin su línea de órdenes ni su entorno no se puede saber si este canal está abierto")


def sin_proceso_legible(servidor):
    """True si H6 no tiene de dónde leer ni la línea de órdenes ni el entorno del servidor: no hay PID y H2-ID no dejó
    opciones ni variables (macOS, WSL, un contenedor visto desde Windows, un servidor solo declarado). Con
    egress.pids o egress.process_names también: esos procesos se observan, pero su línea de órdenes no se analiza."""
    return servidor.pid is None and not servidor.opciones and not servidor.entorno


def _canal_telemetria_vllm(c, s, env, legible, cfg, raiz):
    estado, variable = exclusion_telemetria(env)
    fichero = cfg["history_files"] and (raiz / "do_not_track").is_file()
    cpu = "cpu" in (s.version or "").lower()
    if estado == "valida" or fichero:
        c.cerrado("TELEMETRIA", f"exclusión válida ({variable})" if estado == "valida" else "existe do_not_track en la "
                  "carpeta de estado de vLLM")
    elif estado == "invalida":
        c.abierto("TELEMETRIA-EXCLUSION-INVALIDA", "La exclusión de telemetría de vLLM no tiene un valor que vLLM acepte",
                  Severidad.BAJA, f"{variable} está definida pero vLLM solo la acepta con el valor exacto 1 (con true o "
                  "yes envía igual: medido); no hay otra variable válida ni fichero do_not_track",
                  "Define VLLM_NO_USAGE_STATS=1 o DO_NOT_TRACK=1 (exactamente 1) si no quieres que salgan datos del equipo.")
    elif legible:
        sev = Severidad.INFO if cpu else Severidad.BAJA
        c.abierto("TELEMETRIA", "vLLM envía estadísticas de uso al exterior", sev,
                  "no consta VLLM_NO_USAGE_STATS=1, VLLM_DO_NOT_TRACK=1, DO_NOT_TRACK=1 ni do_not_track; las estadísticas "
                  "llevan hardware, versión y configuración, no prompts"
                  + ("; en la versión para CPU no se envían (solo las llama el worker de GPU)" if cpu else ""),
                  "Define VLLM_NO_USAGE_STATS=1 o DO_NOT_TRACK=1 si no quieres que salgan datos del equipo.",
                  estado="informativo" if cpu else "confirmado")
    else:
        c.abierto("TELEMETRIA", "Telemetría de vLLM sin comprobar", Severidad.BAJA,
                  "el entorno del proceso no es legible (en Windows no se expone a otros procesos; en Linux, solo al "
                  "propietario o a root): no se puede saber si la exclusión está puesta",
                  "Comprueba que VLLM_NO_USAGE_STATS=1 o DO_NOT_TRACK=1 estén definidas si no quieres que salgan datos.",
                  estado="sin_concluir")


def _historial_vllm(c, raiz):
    ruta = raiz / "usage_stats.json"
    try:
        if not ruta.is_file():
            return
        lineas = [x for x in ruta.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        ultima = ""
        try:
            ultima = str(json.loads(lineas[-1]).get("log_time", ""))[:30]
        except (ValueError, AttributeError, IndexError):
            pass
    except OSError:
        return
    c.abierto("TELEMETRIA-HISTORIAL", "Este usuario ya ha enviado (o intentado enviar) estadísticas de vLLM", Severidad.BAJA,
              f"existe usage_stats.json con {len(lineas)} línea(s)" + (f"; la última, {ultima}" if ultima else ""),
              "Define VLLM_NO_USAGE_STATS=1 y, si quieres, borra ese fichero: es la copia local de lo que vLLM envía.")


def _canales_vllm(c, s, env, legible, cfg, expuesto):
    raiz = raiz_config_vllm(env)
    _canal_telemetria_vllm(c, s, env, legible, cfg, raiz)
    if cfg["history_files"]:
        _historial_vllm(c, raiz)
    o = s.opciones
    if o.get("model_remoto") is True:
        sin_offline = not (_verdadero(env.get("HF_HUB_OFFLINE")) or _verdadero(env.get("TRANSFORMERS_OFFLINE")))
        mirror = _host_de(env["HF_ENDPOINT"]) if isinstance(env.get("HF_ENDPOINT"), str) else ""
        destino = ("modelscope.cn" if _verdadero(env.get("VLLM_USE_MODELSCOPE")) else mirror or "huggingface.co")
        if not sin_offline:
            c.cerrado("HUB", "modo sin conexión (HF_HUB_OFFLINE o TRANSFORMERS_OFFLINE)")
        else:
            c.abierto("HUB", "El modelo se pide al hub en línea en cada arranque", Severidad.BAJA,
                      f"el modelo es un identificador de repositorio y no consta HF_HUB_OFFLINE=1; consulta a {destino} "
                      "(revela el nombre del modelo y la IP, y sin el hub el servidor no arranca: medido)",
                      "Arranca con la ruta local del modelo y HF_HUB_OFFLINE=1.", REFS_SUPPLY,
                      estado="confirmado" if legible else "sin_concluir")
    if o.get("load_format") in ("runai_streamer", "tensorizer"):
        c.abierto("CARGA-REMOTA", "Los pesos pueden cargarse desde un almacén remoto", Severidad.BAJA,
                  f"--load-format {o['load_format']}: si el modelo es una URL (s3://, gs://...) se descarga en cada arranque",
                  "Usa pesos locales si no necesitas el almacén remoto.", REFS_SUPPLY, "potencial")
    if o.get("otlp_traces_endpoint"):
        local = _es_host_local(_host_de(o["otlp_traces_endpoint"]))
        sev = Severidad.INFO if local else Severidad.MEDIA
        c.abierto("TRAZAS", "El servidor exporta trazas OTLP", sev,
                  "--otlp-traces-endpoint " + ("local" if local else f"hacia {_host_de(o['otlp_traces_endpoint'])}")
                  + "; las trazas llevan tokens, parámetros, latencias e identificadores, no el texto",
                  "Envía las trazas solo a un colector propio y local." if not local else "",
                  estado="informativo" if local else "confirmado")
    kv = o.get("kv_events_config")
    if kv:
        try:
            datos = json.loads(kv)
        except (TypeError, ValueError):
            datos = {}
        datos = datos if isinstance(datos, dict) else {}
        if datos.get("enable_kv_cache_events") and str(datos.get("publisher", "")).lower() == "zmq":
            endpoint = str(datos.get("endpoint", "tcp://*:5557"))
            abierto = endpoint.startswith(("tcp://*", "tcp://0.0.0.0", "tcp://[::]"))
            sev = Severidad.CRITICA if abierto and expuesto else Severidad.ALTA
            c.abierto("KV-EVENTOS", "vLLM publica los tokens de los prompts por ZMQ sin autenticación", sev,
                      f"--kv-events-config con enable_kv_cache_events y publisher zmq (endpoint {endpoint[:60]}); los eventos "
                      "BlockStored llevan los token_ids del prompt y no hay autenticación",
                      "Desactiva los eventos KV o enlaza el publicador a loopback / una red aislada.")
    if o.get("kv_transfer_config") is True:
        c.abierto("KV-TRANSFER", "La caché KV (derivada de los prompts) puede viajar a otros nodos", Severidad.MEDIA,
                  "--kv-transfer-config presente (no se conserva su valor: puede nombrar otros equipos)",
                  "Comprueba que los nodos de destino son de confianza y están en una red aislada.", estado="potencial")
    tool = o.get("tool_server")
    if tool and not (isinstance(tool, str) and tool.strip().lower() == "demo"):
        hosts = [_host_de(x.strip()) for x in str(tool).split(",") if x.strip()]
        remoto = any(not _es_host_local(h) for h in hosts)
        c.abierto("MCP", "El modelo puede invocar servidores de herramientas", Severidad.ALTA if remoto else Severidad.MEDIA,
                  "--tool-server " + ("con algún host que no es local" if remoto else "local")
                  + "; los argumentos de las herramientas los decide el modelo",
                  "Limita lo que permiten esos servidores y usa solo hosts propios.", REFS_TOOLS)
    if "VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS" in env:
        c.abierto("MCP-ETIQUETAS", "Herramientas internas por MCP configuradas", Severidad.MEDIA,
                  "VLLM_GPT_OSS_SYSTEM_TOOL_MCP_LABELS definida", "Revisa qué permiten esos servidores.", REFS_TOOLS)


def _canales_llamacpp(c, s, env, legible, expuesto):
    o = s.opciones
    sin_offline = not (o.get("offline") is True or _verdadero(env.get("LLAMA_ARG_OFFLINE")))
    descargas = [e for e, clave, variable in (("-mu", "model_url", "LLAMA_ARG_MODEL_URL"), ("-mmu", "mmproj_url", "LLAMA_ARG_MMPROJ_URL"),
                                             ("-hf", "hf_repo", "LLAMA_ARG_HF_REPO"), ("-hfd", "hf_repo_draft", None),
                                             ("-dr", "docker_repo", "LLAMA_ARG_DOCKER_REPO"))
                 if clave in o or (variable and variable in env)]
    if descargas and sin_offline:
        c.abierto("DESCARGA", "El servidor descarga el modelo en cada arranque", Severidad.BAJA,
                  "origen remoto (" + ", ".join(descargas) + ") y no consta --offline: cada arranque consulta el exterior",
                  "Arranca con la ruta local y --offline (o LLAMA_ARG_OFFLINE=1).", REFS_SUPPLY,
                  estado="confirmado" if legible or "offline" in o else "potencial")
    elif descargas:
        c.cerrado("DESCARGA", "origen remoto pero con --offline")
    if "rpc" in o or "LLAMA_ARG_RPC" in env:
        c.abierto("RPC", "El servidor reparte el cálculo por RPC", Severidad.ALTA,
                  "--rpc presente (no se conserva el destino: no se puede comprobar si es local); el protocolo no tiene "
                  "autenticación y los tensores y activaciones, derivados del prompt, viajan a esos equipos",
                  "Usa RPC solo en una red aislada y de confianza.", estado="potencial")
    if any(k in o for k in ("mcp_servers_config", "mcp_servers_json")) or any(
            k in env for k in ("LLAMA_ARG_MCP_SERVERS_CONFIG", "LLAMA_ARG_MCP_SERVERS_JSON")):
        c.abierto("MCP", "El servidor puede invocar servidores MCP", Severidad.MEDIA,
                  "--mcp-servers-config o --mcp-servers-json presente (no se conserva su contenido: puede llevar claves "
                  "y URL remotas)", "Revisa que todos los servidores MCP sean propios y limita sus permisos.", REFS_TOOLS,
                  "potencial")
    if o.get("ui_mcp_proxy") is True or o.get("agent") is True or _verdadero(env.get("LLAMA_ARG_UI_MCP_PROXY")) \
            or _verdadero(env.get("LLAMA_ARG_AGENT")):
        c.abierto("PROXY-UI", "El servidor hace peticiones a las URL que decide el cliente", Severidad.ALTA if expuesto else Severidad.MEDIA,
                  "--ui-mcp-proxy o --agent activos: el proxy CORS reenvía a cualquier URL",
                  "Retira --ui-mcp-proxy y --agent, o exige clave de API.", REFS_TOOLS)
    runtime = str(o.get("tools_runtime", ""))
    if runtime.startswith("docker"):
        c.abierto("HERRAMIENTAS", "Las herramientas se ejecutan en una imagen de Docker", Severidad.INFO,
                  "--tools-runtime docker:<imagen>: se descarga la imagen si no está", "", REFS_TOOLS, "informativo")


def _canal_proxy(c, env):
    proxies = [v for v in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy") if env.get(v)]
    if proxies:
        c.abierto("PROXY", "El servidor sale por un proxy configurado", Severidad.INFO,
                  f"{proxies[0]} definida (no se conserva su valor: puede llevar usuario y clave); lo que salga, sale por ahí",
                  "", REFS_SALIDA, "informativo")


def auditar_canales(servidor, cfg, expuesto):
    """(hallazgos, tabla de canales) de un servidor: función de la línea de órdenes saneada y del entorno."""
    env, legible = entorno_de(servidor)
    c = _Canales()
    if servidor.tipo == "vllm":
        _canales_vllm(c, servidor, env, legible, cfg, expuesto)
    elif servidor.tipo == "llama.cpp":
        _canales_llamacpp(c, servidor, env, legible, expuesto)
        c.cerrado("TELEMETRIA", "llama.cpp no envía telemetría (comprobado en su código y su ayuda)")
    _canal_proxy(c, env)
    if sin_proceso_legible(servidor):
        vistos = {t["canal"] for t in c.tabla}
        for canal in CANALES_DEL_PROCESO.get(servidor.tipo, ()):
            if canal not in vistos:
                c.sin_comprobar(canal, MOTIVO_SIN_PROCESO)
    return c.hallazgos, c.tabla


# ---------------------------------------------------------------------------------------------- canario (HTTP)
_ABRIDOR = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # el servidor es local: nunca por proxy


def _http(url, ruta, cuerpo=None, clave=None, canario=None, timeout=120):
    """(estado | None, texto). POST si hay cuerpo. Sin proxy; nunca lanza."""
    cabeceras = {"User-Agent": "MRRobotIA-H6", "Accept": "application/json"}
    if cuerpo is not None:
        cabeceras["Content-Type"] = "application/json"
    if clave:
        cabeceras["Authorization"] = f"Bearer {clave}"
    if canario:
        cabeceras["X-Request-Id"] = canario
    peticion = urllib.request.Request(url.rstrip("/") + ruta, None if cuerpo is None else json.dumps(cuerpo).encode(),
                                      cabeceras)
    try:
        with _ABRIDOR.open(peticion, timeout=timeout) as r:
            return r.status, r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def _modelo_servido(url, clave):
    estado, texto = _http(url, "/v1/models", clave=clave, timeout=5)
    try:
        return str(json.loads(texto)["data"][0]["id"]) if estado == 200 else None
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def _responde(url, clave, espera=5.0, dormir=time.sleep):
    """¿Contesta /health (o /v1/models) con 200 en `espera` s?"""
    limite = time.monotonic() + espera
    while True:
        for ruta in ("/health", "/v1/models"):
            if _http(url, ruta, clave=clave, timeout=2)[0] == 200:
                return True
        if time.monotonic() >= limite:
            return False
        dormir(0.5)


def peticion_canario(tipo_servidor, endpoint, texto, modelo, max_tokens):
    """(ruta, cuerpo) de una petición con el canario en el contenido."""
    if endpoint == "chat":
        cuerpo = {"messages": [{"role": "user", "content": texto}], "max_tokens": max_tokens, "temperature": 0}
        ruta = "/v1/chat/completions"
    elif endpoint == "completion":
        if tipo_servidor == "llama.cpp":
            return "/completion", {"prompt": texto, "n_predict": max_tokens, "temperature": 0}
        cuerpo, ruta = {"prompt": texto, "max_tokens": max_tokens, "temperature": 0}, "/v1/completions"
    else:
        if tipo_servidor == "llama.cpp":
            return "/tokenize", {"content": texto}
        cuerpo, ruta = {"prompt": texto}, "/tokenize"
    if modelo and tipo_servidor == "vllm":
        cuerpo["model"] = modelo
    return ruta, cuerpo


# ---------------------------------------------------------------------------------------------- módulo
class H6Salidas(Modulo):
    nombre = MODULO
    titulo = "Salidas de datos a la red"
    hito = "H6"
    etiqueta_escaneo = "egress"
    tipo = "hibrido"
    activo = False
    en_all = True
    requiere_servidor = True
    descripcion = ("Audita los canales por los que el servidor puede sacar datos (telemetría, descargas, RPC, MCP, trazas, "
                   "eventos KV) y observa las conexiones salientes de su árbol de procesos; con -a envía peticiones con "
                   "un canario y correlaciona")
    # Lo fija el CLI: el escaneo se pidió por su etiqueta (-s egress), lo que permite la ventana pasiva sin -a.
    pedido_explicito = False
    # Puntos de inyección de las pruebas.
    _reloj = staticmethod(time.monotonic)
    _dormir = staticmethod(time.sleep)
    _leer_procesos = None
    _leer_sockets = None
    _resolver = staticmethod(socket.getaddrinfo)
    _propias_extra = ()

    def ejecutar(self, objetivo):
        if self.contexto is None:
            return [self.hallazgo_sin_contexto()]
        cfg, error = validar_config(objetivo.get("egress"))
        if error:
            return [Hallazgo(MODULO, "H6-SALIDAS-CONFIG", "Configuración de egress no válida", Severidad.MEDIA, "sin_concluir",
                             error + "; no se ha observado nada",
                             "Corrige el bloque egress del objetivo (ver la guía, docs/GUIA.md).")]
        reglas, nombres, error = parsear_permitidas(cfg["allow"], self._resolver)
        if error:
            return [Hallazgo(MODULO, "H6-SALIDAS-CONFIG", "Configuración de egress no válida", Severidad.MEDIA, "sin_concluir",
                             error + "; no se ha observado nada", "Corrige egress.allow.")]
        hallazgos = []
        if nombres:
            hallazgos.append(Hallazgo(MODULO, "H6-SALIDAS-ALLOW-DNS", "egress.allow incluye nombres, resueltos por DNS",
                                      Severidad.INFO, "informativo",
                                      f"se resolvieron {len(nombres)} nombre(s) una sola vez al empezar (una consulta DNS)", ""))
        servidores = [s for s in self.contexto.servidores if s.tipo in TIPOS_SERVIDOR]
        for servidor in servidores:
            parciales = []
            try:
                self._servidor(servidor, objetivo, cfg, reglas, parciales)
            except Exception as e:      # invariante: un fallo nunca llega al llamador
                parciales.append(Hallazgo(MODULO, "H6-SALIDAS-ERROR", "Error al evaluar las salidas", Severidad.INFO,
                                          "sin_concluir", type(e).__name__, ""))
            hallazgos.extend(rotular(parciales, servidor))
        if not servidores:
            hallazgos.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-DATOS", "Sin servidor que auditar", Severidad.INFO, "informativo",
                                      "H2-ID no ha identificado ningún servidor llama.cpp ni vLLM", ""))
        return hallazgos

    # ------------------------------------------------------------------------------------------ un servidor
    def _servidor(self, s, objetivo, cfg, reglas, h):
        if not red.es_host_local(s.host):
            h.append(Hallazgo(MODULO, "H6-SALIDAS-NO-LOCAL", "H6 solo observa procesos de este equipo", Severidad.INFO,
                              "sin_concluir", "el servidor no está en esta máquina: H6 observa procesos y sockets locales",
                              "Ejecuta MRRobotIA en la máquina del servidor."))
            return
        expuesto = red.es_no_loopback(s.enlace)
        canales, tabla = auditar_canales(s, cfg, expuesto)
        h.extend(canales)
        if self.contexto.so not in ("windows", "linux"):
            # Sin lectura de procesos ni de sockets: no se observa ni se envía ningún canario, aunque haya egress.pids.
            h.append(Hallazgo(
                MODULO, "H6-SALIDAS-SO-NO-SOPORTADO", "H6 no puede observar procesos ni sockets en este sistema",
                Severidad.INFO, "sin_concluir",
                f"sistema «{self.contexto.so}»: H6 solo lee la tabla de procesos y de sockets en Windows y Linux, así que no "
                "se ha observado ninguna conexión ni se ha enviado ningún canario (aunque se declararan egress.pids o "
                "egress.process_names)" + SUFIJO_ESTATICA,
                "Ejecuta MRRobotIA en Windows o Linux, o dentro de WSL o del contenedor del servidor, para observar sus "
                "conexiones; mientras tanto, revisa a mano los canales sin comprobar y bloquea la salida con el cortafuegos."))
            self._resumen(h, s, cfg, tabla, [], None, None, [], expuesto)
            return
        if s.pid is None and not cfg["pids"] and not cfg["process_names"]:
            if self.contexto.so == "windows":
                h.append(Hallazgo(
                    MODULO, "H6-SALIDAS-WSL", "El servidor no tiene un proceso visible desde Windows", Severidad.INFO,
                    "sin_concluir", "responde pero no hay un proceso local asociado: probablemente corre dentro de WSL o de "
                    "un contenedor, y Windows solo ve wslrelay.exe, no sus procesos ni su tráfico; no se ha observado "
                    "ninguna conexión" + SUFIJO_ESTATICA,
                    "Ejecuta MRRobotIA dentro de WSL (python3 -m mrrobotia ...) para observar sus conexiones."))
            else:
                h.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-PID", "No se conoce el proceso del servidor", Severidad.INFO,
                                  "sin_concluir", "no hay un proceso local asociado; no se ha observado ninguna conexión"
                                  + SUFIJO_ESTATICA,
                                  "Indica el PID en egress.pids o el nombre en egress.process_names."))
            self._resumen(h, s, cfg, tabla, [], None, None, [], expuesto)
            return
        observar_pasiva = cfg["passive_window"] > 0 and (self.activos_ok or self.pedido_explicito)
        pasiva = activa = None
        envios, ok = [], 0
        raices = ([s.pid] if s.pid else []) + list(s.pids_hijos) + cfg["pids"]
        if (observar_pasiva or self.activos_ok) and not self._arbol_visible(raices, cfg["process_names"]):
            # Los PID o nombres declarados no existen al empezar: no se observa y, sobre todo, no se envía ningún canario.
            h.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-PID", "No se encontró el proceso del servidor",
                              Severidad.INFO, "sin_concluir",
                              "ni el PID ni los nombres indicados existían al empezar; no se ha observado ninguna conexión "
                              "ni se ha enviado ningún canario" + SUFIJO_ESTATICA,
                              "Comprueba que egress.pids o egress.process_names son los del servidor y que sigue arrancado."))
            observar_pasiva = False
            if self.activos_ok:
                self._resumen(h, s, cfg, tabla, [], None, None, [], expuesto)
                return
        elif observar_pasiva or self.activos_ok:
            t0 = self._reloj()
            comunes = dict(nombres=cfg["process_names"], permitidas=reglas, propias_extra=self._propias_extra,
                           puerto_api=s.puerto, reloj=self._reloj, dormir=self._dormir, leer_procesos=self._leer_procesos,
                           leer_sockets=self._leer_sockets, t0=t0)
            intervalo = cfg["interval_ms"] / 1000
            if observar_pasiva:
                print(f"H6: observando las conexiones de {s.tipo} (PID {s.pid}) durante {cfg['passive_window']} s", flush=True)
                pasiva = observar(raices, cfg["passive_window"], intervalo, ventana="pasiva", **comunes)
            if self.activos_ok:
                if pasiva is not None and not self._arbol_visible(raices, cfg["process_names"]):
                    # El árbol dejó de verse durante la pasiva (¿reinicio con otro PID?): ningún canario sin observar.
                    if pasiva.pids:
                        h.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-PID", "El proceso del servidor dejó de verse tras la "
                                          "ventana pasiva", Severidad.INFO, "sin_concluir",
                                          "el árbol del servidor se vio en la ventana pasiva pero no al empezar la activa; "
                                          "no se ha enviado ningún canario",
                                          "Comprueba que el servidor sigue arrancado (un reinicio cambia su PID) y repite."))
                else:
                    activa, envios, ok, extra = self._ventana_activa(s, cfg, raices, intervalo, comunes)
                    h.extend(extra)
        if not self.activos_ok:
            h.append(Hallazgo(MODULO, "H6-SALIDAS-CANARIO-OMITIDO", "Canario no enviado", Severidad.INFO, "informativo",
                              "solo se ha hecho la auditoría estática" + (" y la ventana pasiva" if pasiva else "")
                              + ": la ventana con canario exige -a con allow_active; la ventana pasiva, -a o pedir "
                              "el escaneo con -s egress",
                              "Repite con -a y allow_active=true para observar las conexiones con tráfico de canario."))
        self._resumen(h, s, cfg, tabla, envios, pasiva, activa, [], expuesto, ok)

    def _arbol_visible(self, raices, nombres):
        """¿Se ve ahora al menos un proceso del árbol? Lo mismo que usa `observar`; nunca lanza."""
        try:
            tabla = (self._leer_procesos or procesos.tabla_pid_ppid)()
            nombres = {n.lower() for n in nombres}
            todas = set(raices) | {p for p, (_, n) in tabla.items() if n.lower() in nombres}
            return bool(procesos.arbol_de(tabla, todas))
        except Exception:
            return False

    def _ventana_activa(self, s, cfg, raices, intervalo, comunes):
        """(observación, envíos, nº ok, hallazgos extra). Hilo de muestreo + peticiones con canario en el principal."""
        extra = []
        clave = os.environ.get(cfg["api_key_env"]) or None
        if not _responde(s.url, clave, 5.0, self._dormir):
            extra.append(Hallazgo(MODULO, "H6-SALIDAS-CANARIO-SIN-RESPUESTA", "El servidor no responde: sin canario",
                                  Severidad.INFO, "sin_concluir", "ni /health ni /v1/models dan 200 en 5 s; no se ha enviado nada",
                                  "Comprueba que el servidor está arrancado y que la clave (api_key_env) es la correcta."))
            return None, [], 0, extra
        modelo = _modelo_servido(s.url, clave) if s.tipo == "vllm" else None
        marca = f"MRR-H6-{uuid.uuid4().hex[:12]}"
        parar, resultado = threading.Event(), {}
        total = cfg["active_window"] + cfg["trailing"]

        def hilo():
            resultado["obs"] = observar(raices, total, intervalo, ventana="activa", parar=parar, **comunes)
        print(f"H6: enviando {cfg['canaries']} peticiones con canario a {s.tipo} durante {cfg['active_window']} s "
              f"(y {cfg['trailing']} s más de observación)", flush=True)
        t = threading.Thread(target=hilo, daemon=True)
        t.start()
        envios, ok, hueco = [], 0, cfg["active_window"] / cfg["canaries"]
        inicio = self._reloj()
        for i in range(cfg["canaries"]):
            espera = inicio + i * hueco - self._reloj()
            if espera > 0:
                self._dormir(espera)
            ruta, cuerpo = peticion_canario(s.tipo, cfg["canary_endpoint"], f"Repite exactamente: {marca}-{i}", modelo,
                                            cfg["max_tokens"])
            envios.append((self._reloj() - comunes["t0"], None))
            estado, _ = _http(s.url, ruta, cuerpo, clave, marca)
            envios[-1] = (envios[-1][0], estado == 200)
            ok += estado == 200
            if i == 0 and not _responde(s.url, clave, 5.0, self._dormir):
                extra.append(Hallazgo(
                    MODULO, "H6-SALIDAS-SERVIDOR-CAIDO", "El servidor dejó de responder tras la primera petición con canario",
                    Severidad.MEDIA, "confirmado", "ni /health ni /v1/models responden tras la primera petición; no se envían "
                    "más (un vLLM en CPU sin compilador cae al generar: prueba egress.canary_endpoint = tokenize)",
                    "Revisa el registro del servidor; la petición con canario no debería tumbarlo."))
                break
        # Se deja correr la ventana hasta el final de active_window + trailing.
        t.join(timeout=total + 30)
        parar.set()
        t.join(timeout=5)
        return resultado.get("obs"), envios, ok, extra

    # ------------------------------------------------------------------------------------------ síntesis
    def _resumen(self, h, s, cfg, tabla, envios, pasiva, activa, _, expuesto, ok=0):
        observadas = [o for o in (pasiva, activa) if o is not None]
        conexiones = []
        hay_salidas = False
        if observadas:
            meta = {"intervalo_ms": cfg["interval_ms"], "correlacion_s": cfg["correlation_s"],
                    "puertos_internos": perfil_de(s).puertos_internos}
            extra, conexiones, hay_salidas = hallazgos_desde_observacion(pasiva, activa, envios, meta)
            h.extend(extra)
        # Una ventana en la que no se vio el árbol no cuenta como limpia (sus segundos no suman en VENTANA-LIMPIA).
        total_s = round(sum(o.segundos for o in observadas if o.pids), 1)
        sin_arbol = bool(observadas) and not any(o.pids for o in observadas)
        perdidas = [o.ventana for o in observadas if not o.pids] if not sin_arbol else []
        if sin_arbol:
            h.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-PID", "No se encontró el proceso del servidor durante la observación",
                              Severidad.INFO, "sin_concluir", "ni el PID ni los nombres indicados existían durante la ventana; "
                              "no se ha observado ninguna conexión" + SUFIJO_ESTATICA,
                              "Comprueba que egress.pids o egress.process_names son los del servidor y que sigue arrancado."))
        elif perdidas:
            h.append(Hallazgo(MODULO, "H6-SALIDAS-SIN-PID", "El proceso del servidor dejó de verse durante la observación",
                              Severidad.INFO, "sin_concluir",
                              f"el árbol del servidor no se vio en la ventana {', '.join(perdidas)}: lo que hiciera entonces "
                              "no se ha observado y esa ventana no cuenta como limpia",
                              "Comprueba que el servidor sigue arrancado (un reinicio cambia su PID) y repite."))
        if observadas and not hay_salidas and not sin_arbol:
            h.append(Hallazgo(MODULO, "H6-SALIDAS-VENTANA-LIMPIA", "Sin salidas durante la observación", Severidad.INFO,
                              "informativo", frase_ventana_limpia(total_s, cfg["interval_ms"]), "", REFS_SALIDA))
        muestras = sum(o.muestras for o in observadas)
        coste = round(sum(o.coste_ms * o.muestras for o in observadas) / muestras, 1) if muestras else 0
        pids = {}
        for o in observadas:
            pids.update(o.pids)
        publicas = sum(1 for c in conexiones if c["clase"] == "publica")
        privadas = sum(1 for c in conexiones if c["clase"] == "privada")
        abiertos = [t["canal"] for t in tabla if t["estado"] in ("abierto", "posible")]
        sin_comprobar = [t["canal"] for t in tabla if t["estado"] == "sin comprobar"]
        cabecera = (f"H6 · {s.tipo} PID {s.pid if s.pid is not None else '?'} · árbol {len(pids)} proceso(s) · "
                    f"pasiva {pasiva.segundos if pasiva else 0:g} s · activa {activa.segundos if activa else 0:g} s · "
                    f"{len(envios)} canario(s) ({ok} OK) · {muestras} muestra(s) ({coste} ms/muestra) · salidas: "
                    f"{publicas} públicas, {privadas} privadas · canales abiertos: "
                    f"{', '.join(abiertos) or ('ninguno de los comprobados' if sin_comprobar else 'ninguno')}"
                    + (f" · canales sin comprobar: {', '.join(sin_comprobar)}" if sin_comprobar else ""))
        limites = None
        if observadas and not hay_salidas and not sin_arbol:
            limites = frase_ventana_limpia(total_s, cfg["interval_ms"])
        h.append(Hallazgo(MODULO, "H6-SALIDAS-RESUMEN", "Resumen de las salidas de datos", Severidad.INFO, "informativo",
                          cabecera, "", REFS_SALIDA,
                          {"seccion": "egress", "tipo": "resumen", "cabecera": cabecera, "canales": tabla,
                           "conexiones": conexiones, "limites": limites}))
