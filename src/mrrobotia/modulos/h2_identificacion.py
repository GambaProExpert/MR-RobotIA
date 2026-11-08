"""
H2-ID — Identificación: qué servidor LLM hay, en qué versión, cómo se arrancó y en qué SO.

Corre SIEMPRE y primero (lo garantiza el CLI) y deja en `self.contexto` un `Contexto` que los
demás módulos usan para adaptar sus pruebas. Módulo HÍBRIDO, como H2 y H3:

- PASIVO (siempre): SO, procesos y tabla de puertos. No toca la red y, si el host auditado no
  es este equipo, tampoco mira sus procesos: serían los del auditor.
- ACTIVO (solo con --permitir-activos y permitir_activos=true; si el host no es local, además
  con autorizacion.confirmo_no_local): pregunta por HTTP a cada candidato con `ClienteHTTP`,
  que solo permite GET, HEAD y OPTIONS. Julius se usa únicamente para lo que los perfiles no
  reconocen, y siempre con sondas GET propias: las 64 por defecto pueden enviar un prompt.

Combinación: un proceso y una respuesta HTTP del mismo puerto son un único servidor. Prioridad:
forzado (--servidor), proceso, HTTP, Julius, declarado (`servidor` del objetivo).

INVARIANTE DE PRIVACIDAD: la línea de órdenes solo se pasa por la lista blanca del perfil. Al
informe llegan opciones saneadas, nombres de fichero de los modelos y señales cortas; la salida
de error de Julius, que puede llevar URL, no se guarda.

Atacantes del modelo de amenazas: A5 (servicio alcanzable) y A3 (procesos locales). Marcos:
OWASP LLM Top 10 2025 (LLM10), MITRE ATLAS (AML.T0049) y NIST AI 600-1 (2.9).
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from mrrobotia import herramientas, procesos, red
from mrrobotia.contexto import Contexto, ServidorDetectado, texto_enlace
from mrrobotia.herramientas import Herramienta
from mrrobotia.nucleo import Hallazgo, Modulo, Severidad
from mrrobotia.perfiles import GENERICO, PERFILES
from mrrobotia.perfiles.base import MAX_MODELOS, Identificacion, limpiar, nombre_modelo

MODULO = "H2-ID"
REFS = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}
TIMEOUT_HTTP = 3            # s por petición: un servidor sano contesta a estas rutas al instante
TIMEOUT_JULIUS = 30         # s para el proceso completo de Julius
# En loopback, un puerto abierto acepta al instante, y Windows tarda 2 s en dar uno por cerrado.
TIMEOUT_CONEXION_LOCAL = 0.5

JULIUS = Herramienta(
    nombre="julius", binario="julius", version_args=None,
    instalar_con="go install github.com/praetorian-inc/julius/cmd/julius@v1.6.0", refs=REFS)
DIR_SONDAS = Path(__file__).resolve().parent.parent / "datos" / "julius_sondas"
SERVICIOS_JULIUS = {"llama-cpp": "llama.cpp", "vllm": "vllm"}

_ALIAS_TIPO = {"llama.cpp": "llama.cpp", "llamacpp": "llama.cpp", "llama-cpp": "llama.cpp",
               "llama_cpp": "llama.cpp", "llama-server": "llama.cpp", "vllm": "vllm",
               "generico": "generico"}
_RE_SUFIJO_API = re.compile(r"/(?:v\d+(?:/.*)?|chat/completions|completions?|embeddings?|models|health|props)/?$")
_VARIABLES_PROXY = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}


@dataclass
class _Destino:
    """Lo que declara el objetivo: dónde debería estar el servidor."""
    esquema: str
    host: str
    puerto: int | None
    prefijo: str


@dataclass
class _Candidato:
    """Dirección a la que preguntar por HTTP."""
    esquema: str
    host: str
    puerto: int
    prefijo: str = ""
    por_defecto: bool = False   # solo es un puerto por defecto de un perfil: nadie lo ha indicado

    @property
    def raiz(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.esquema}://{host}:{self.puerto}"

    @property
    def url(self):
        return self.raiz + self.prefijo


# ----------------------------------------------------- funciones puras: objetivo
def _prefijo_de_ruta(ruta):
    """Prefijo del servidor según la ruta del endpoint: lo que precede a la API."""
    return _RE_SUFIJO_API.sub("", ruta or "").rstrip("/")


def _destino(objetivo):
    """Interpreta `endpoint`, `host` y `exposicion.puerto` del objetivo."""
    cfg = objetivo.get("exposicion") or {}
    host = objetivo.get("host") or cfg.get("host") or "127.0.0.1"
    puerto = red.a_puerto(cfg.get("puerto"))
    esquema, prefijo = "http", ""
    endpoint = objetivo.get("endpoint")
    if endpoint:
        try:
            partes = urllib.parse.urlsplit(str(endpoint))
            esquema = (partes.scheme or "http").lower()
            host = partes.hostname or host
            puerto = partes.port or puerto or (443 if esquema == "https" else 80)
            prefijo = _prefijo_de_ruta(partes.path)
        except ValueError:
            pass
    return _Destino(esquema, host, puerto, prefijo)


def _tipo_normalizado(valor):
    """Tipo canónico de un servidor declarado o forzado; None si no se indica."""
    if not isinstance(valor, str) or not valor.strip():
        return None
    texto = valor.strip().lower()
    if texto.startswith("otro:"):
        return limpiar(texto, 60)
    return _ALIAS_TIPO.get(texto, f"otro:{limpiar(texto, 40)}")


def _enlace_de_opcion(valor, defecto):
    """Enlace según --host: si es una lista, el de mayor exposición."""
    clases = [c for c in (red.clasificar_direccion(p) for p in str(valor or "").split(",")) if c]
    if not clases:
        return defecto
    if "todas" in clases:
        return "todas"
    return next((c for c in clases if isinstance(c, tuple)), "loopback")


def _host_conexion(valor):
    """Dirección para conectar con un proceso local según su --host."""
    for parte in str(valor or "").split(","):
        clase = red.clasificar_direccion(parte)
        if isinstance(clase, tuple):
            return clase[1]
        if clase == "loopback":
            return parte.strip().strip("[]")
    return "127.0.0.1"


def interpretar_julius(salida):
    """Convierte la salida JSON de Julius en una `Identificacion`, o None si no reconoce nada.

    Vale el resultado de mayor `specificity`; si hay varios empatados no se elige uno a ciegas
    (el orden depende de la concurrencia) y se marca como ambiguo. `auth_required` falso solo
    dice que la sonda coincidió sin credenciales, quizá en una ruta pública: no prueba que la
    API esté abierta.
    """
    try:
        datos = json.loads(salida or "[]")
    except ValueError:
        return None
    if not isinstance(datos, list):
        return None
    validos = [d for d in datos if isinstance(d, dict) and isinstance(d.get("service"), str)
               and d["service"] != "openai-compatible"]
    if not validos:
        return None
    especificidad = [d.get("specificity") if isinstance(d.get("specificity"), int) else 0 for d in validos]
    mayor = max(especificidad)
    mejores = [d for d, e in zip(validos, especificidad) if e == mayor]
    servicios = sorted({limpiar(d["service"], 40) for d in mejores})
    d = mejores[0]
    modelos = d.get("models") if isinstance(d.get("models"), list) else []
    nombres = [n for n in (nombre_modelo(m) for m in modelos[:MAX_MODELOS]) if n]
    autenticacion = "activa" if d.get("auth_required") is True else "indeterminada"
    if len(servicios) > 1:
        return Identificacion(f"otro:{servicios[0]}", "baja", None, autenticacion,
                              ["julius ambiguo: " + ", ".join(servicios)], nombres)
    servicio = servicios[0]
    return Identificacion(SERVICIOS_JULIUS.get(servicio, f"otro:{servicio}"), "media", None,
                          autenticacion, [f"julius: {servicio}"], nombres)


# ------------------------------------------------------------- recogida local
def _detectar_so():
    """(so, wsl). El SO en minúsculas, con 'macos' en lugar de 'darwin'."""
    sistema = platform.system().lower()
    so = {"darwin": "macos"}.get(sistema, sistema or "desconocido")
    wsl = False
    if so == "linux":
        try:
            with open("/proc/version", encoding="utf-8", errors="replace") as f:
                wsl = "microsoft" in f.read().lower()
        except OSError:
            pass
    return so, wsl


def _es_local(host):
    """¿El host auditado es este equipo? Solo entonces sus procesos son los del objetivo."""
    if red.clasificar_direccion(host) in ("loopback", "todas"):
        return True
    texto = str(host).lower()
    return texto in {socket.gethostname().lower(), (red.ip_rutable() or "").lower()}


def _servidor_de_proceso(perfil, proceso, tabla):
    opciones = perfil.analizar_argv(proceso.argv)
    entorno = procesos.leer_entorno(proceso.pid, perfil.variables)
    host, puerto = perfil.puerto_y_host(opciones, entorno)
    sin_tcp = "uds" in opciones or str(opciones.get("host", "")).endswith(".sock")
    if puerto is None and not sin_tcp:
        puertos = red.puertos_de_pid(tabla, proceso.pid)
        puerto = puertos[0] if puertos else None
    # Sin argumentos visibles no se sabe si indicó --host: no vale el enlace por defecto.
    respaldo = None if sin_tcp or len(proceso.argv) < 2 else _enlace_de_opcion(host, perfil.enlace_defecto)
    senales = [f"proceso {perfil.nombre}"] + (["socket UNIX: sin puerto TCP"] if sin_tcp else [])
    return ServidorDetectado(
        tipo=perfil.id, host=_host_conexion(host), puerto=puerto,
        esquema=perfil.esquema_de(opciones, entorno), prefijo=perfil.prefijo_de(opciones, entorno),
        confianza="media", fuentes=["proceso"], pid=proceso.pid,
        enlace=(red.bind_desde_tabla(tabla, puerto) if puerto else None) or respaldo,
        opciones=opciones, entorno=entorno, autenticacion=perfil.autenticacion_de(opciones, entorno),
        modelos=perfil.modelos_de(opciones), senales=senales)


def _depurar(servidores):
    """Quita lo repetido: el mismo puerto, y los hijos de los que solo se ve el título si ya
    consta el servidor principal (o varios hermanos)."""
    principales = {s.tipo for s in servidores if s.puerto is not None or s.opciones}
    resultado, puertos, hijos = [], set(), set()
    for s in servidores:
        if s.puerto is None and not s.opciones:
            if s.tipo in principales or s.tipo in hijos:
                continue
            hijos.add(s.tipo)
        elif s.puerto is not None:
            if (s.tipo, s.puerto) in puertos:
                continue
            puertos.add((s.tipo, s.puerto))
        resultado.append(s)
    return resultado


def _desde_procesos(tabla):
    """(servidores reconocidos, ¿se pudo enumerar?). Un equipo siempre tiene procesos: una
    lista vacía significa que la enumeración falló, no que no haya ninguno."""
    lista = procesos.enumerar()
    servidores = []
    for proceso in lista:
        perfil = next((p for p in PERFILES if p.reconoce_proceso(proceso.argv)), None)
        if perfil is not None:
            servidores.append(_servidor_de_proceso(perfil, proceso, tabla))
    return _depurar(servidores), bool(lista)


# ------------------------------------------------------- candidatos y combinación
def _candidatos(destino, servidores):
    """El endpoint declarado, los puertos de los procesos y los puertos por defecto de cada
    perfil, sin repetir puerto. Un proceso del puerto declarado aporta su prefijo y esquema."""
    lista, puertos = [], set()

    def anadir(esquema, host, puerto, prefijo, por_defecto=False):
        if puerto and puerto not in puertos:
            puertos.add(puerto)
            lista.append(_Candidato(esquema, host, puerto, prefijo, por_defecto))

    propio = next((s for s in servidores if s.puerto == destino.puerto), None)
    anadir(propio.esquema if propio else destino.esquema, destino.host, destino.puerto,
           destino.prefijo or (propio.prefijo if propio else ""))
    for s in servidores:
        anadir(s.esquema, s.host, s.puerto, s.prefijo)
    for perfil in PERFILES:
        for puerto in perfil.puertos_defecto:
            anadir("http", destino.host, puerto, "", por_defecto=True)
    return lista


def _fusionar(servidor, ident, fuente):
    """Añade a un servidor conocido lo observado por red. El tipo ya establecido manda: un
    proceso gana a HTTP, salvo que HTTP no diga nada más que «compatible con OpenAI»."""
    if fuente not in servidor.fuentes:
        servidor.fuentes.append(fuente)
    if servidor.tipo == ident.tipo:
        servidor.version = ident.version or servidor.version
        servidor.confianza = "alta"
    elif ident.tipo != GENERICO.id:
        servidor.senales.append(f"la red apunta a {ident.tipo}, pero el proceso es {servidor.tipo}")
    if ident.autenticacion and (servidor.autenticacion is None or ident.autenticacion != "indeterminada"):
        servidor.autenticacion = ident.autenticacion
    servidor.senales.extend(x for x in ident.senales if x not in servidor.senales)
    servidor.modelos.extend(m for m in ident.modelos if m not in servidor.modelos)


def _incorporar(servidores, candidato, ident, fuente, tabla):
    """Une una identificación por red con el servidor del mismo puerto o la añade como nuevo."""
    puerto = candidato.puerto
    existente = next((s for s in servidores if s.puerto == puerto), None)
    if existente is None:
        # Un proceso sin puerto conocido: este es el suyo si coincide el tipo.
        existente = next((s for s in servidores if s.puerto is None and s.tipo == ident.tipo
                          and "proceso" in s.fuentes), None)
        if existente is not None:
            existente.puerto, existente.host, existente.esquema = puerto, candidato.host, candidato.esquema
            existente.prefijo = existente.prefijo or candidato.prefijo
            existente.enlace = red.bind_desde_tabla(tabla, puerto) or existente.enlace
    if existente is not None:
        _fusionar(existente, ident, fuente)
        return
    servidores.append(ServidorDetectado(
        tipo=ident.tipo, host=candidato.host, puerto=puerto, esquema=candidato.esquema,
        prefijo=candidato.prefijo, version=ident.version, confianza=ident.confianza,
        fuentes=[fuente], pid=red.pid_desde_tabla(tabla, puerto),
        enlace=red.bind_desde_tabla(tabla, puerto), autenticacion=ident.autenticacion,
        modelos=list(ident.modelos), senales=list(ident.senales)))


def _solo_declarado(servidor):
    return servidor.fuentes == ["declarado"]


# -------------------------------------------------------------------- hallazgos
def _direccion(servidor):
    if servidor.puerto is None:
        return f"{servidor.host} (puerto desconocido)"
    return f"{servidor.host}:{servidor.puerto}"


def _evidencia_servidor(s):
    partes = [f"{s.tipo} {s.version or '(versión desconocida)'} en {_direccion(s)}",
              f"fuentes: {', '.join(s.fuentes)}", f"confianza: {s.confianza}",
              f"enlace: {texto_enlace(s.enlace)}", f"autenticación: {s.autenticacion or 'sin comprobar'}"]
    if s.pid is not None:
        partes.append(f"pid {s.pid}")
    return "; ".join(partes)


def _hallazgo_servidor(s):
    if s.tipo.startswith("otro:"):
        return Hallazgo(
            MODULO, "H2-ID-OTRO", f"Servicio identificado sin perfil propio: {s.tipo[5:]}",
            Severidad.INFO, "informativo", _evidencia_servidor(s),
            "MRRobotIA solo tiene perfil propio para llama.cpp y vLLM: sobre este servicio solo se "
            "aplicarán las comprobaciones comunes.", REFS)
    titulo = ("Servidor compatible con OpenAI, sin más información" if s.tipo == GENERICO.id
              else f"Servidor identificado: {s.tipo}")
    return Hallazgo(MODULO, "H2-ID-SERVIDOR", titulo, Severidad.INFO, "informativo",
                    _evidencia_servidor(s), "", REFS)


def _conflicto(evidencia):
    return Hallazgo(
        MODULO, "H2-ID-CONFLICTO", "Lo declarado en el objetivo contradice lo detectado",
        Severidad.MEDIA, "confirmado", evidencia,
        "Corrige el objetivo o revisa qué se está sirviendo en ese puerto: la auditoría podría "
        "estar apuntando a un servicio distinto del previsto.", REFS)


# ------------------------------------------------------------------------- módulo
class H2Identificacion(Modulo):
    nombre = MODULO
    titulo = "Identificación del servidor LLM y del sistema"
    activo = False               # HÍBRIDO: se ejecuta siempre y autogatea con self.activos_ok
    etiqueta_escaneo = "identificacion"
    # Tipo impuesto por el usuario (--servidor): gana a lo detectado, avisando si difiere.
    servidor_forzado = None

    def ejecutar(self, objetivo):
        so, wsl = _detectar_so()
        self.contexto = Contexto(so=so, wsl=wsl)
        self._julius_avisada = False
        hallazgos = [Hallazgo(MODULO, "H2-ID-SO", "Sistema operativo del host auditor", Severidad.INFO,
                              "informativo", so + (" (WSL)" if wsl else ""), "", REFS)]
        try:
            self._identificar(objetivo, hallazgos)
        except Exception as e:      # invariante: un fallo nunca llega al llamador
            hallazgos.append(Hallazgo(
                MODULO, "H2-ID-ERROR", "Error durante la identificación", Severidad.INFO, "informativo",
                type(e).__name__, "Los módulos siguientes tendrán menos información del servidor.", REFS))
        return hallazgos

    def _motivo_omision(self, objetivo, local):
        """Por qué no se puede sondear por red, o None si se puede."""
        if not local and objetivo.get("autorizacion", {}).get("confirmo_no_local") is not True:
            return "host no local sin confirmo_no_local"
        if not getattr(self, "activos_ok", False):
            return "requiere --permitir-activos y permitir_activos=true"
        return None

    def _identificar(self, objetivo, h):
        destino = _destino(objetivo)
        local = _es_local(destino.host)
        tabla = red.tabla_puertos() if local else ""
        servidores, enumerados = _desde_procesos(tabla) if local else ([], False)
        cerrados = []
        omision = self._motivo_omision(objetivo, local)
        if omision:
            h.append(Hallazgo(
                MODULO, "H2-ID-ACTIVO-OMITIDO", "Identificación por red omitida", Severidad.INFO, "informativo",
                omision, "Sin el sondeo activo no se obtienen versión ni autenticación del servidor.", REFS))
        else:
            self._sondear_candidatos(objetivo, destino, local, servidores, tabla, cerrados, h)
        self._aplicar_declaraciones(objetivo, destino, servidores, h)
        for s in servidores:
            if _solo_declarado(s) and s.puerto in cerrados:
                s.senales.append("puerto cerrado en el sondeo activo")
        servidores.sort(key=lambda s: 0 if s.puerto == destino.puerto else 1)
        self.contexto.servidores = servidores
        if not local:
            procedencia = "no se inspeccionan procesos: el host no es este equipo"
        else:
            procedencia = "ningún proceso reconocido" if enumerados else "no se pudieron enumerar los procesos"
        self._informar(destino, servidores, procedencia, omision, cerrados, h)

    # ----------------------------------------------------------------- sondeo
    def _sondear_candidatos(self, objetivo, destino, local, servidores, tabla, cerrados, h):
        for c in _candidatos(destino, servidores):
            espera = TIMEOUT_CONEXION_LOCAL if local and c.por_defecto else red.TIMEOUT_SONDEO
            if not red.sondear(c.host, c.puerto, timeout=espera):
                cerrados.append(c.puerto)
                continue
            cliente = red.ClienteHTTP(c.url, timeout=TIMEOUT_HTTP)
            try:
                ident, fuente = self._identificar_candidato(c, cliente, objetivo, h)
            except Exception as e:      # un candidato raro no debe impedir ver los demás
                h.append(Hallazgo(
                    MODULO, "H2-ID-ERROR", "Error al identificar un candidato", Severidad.INFO,
                    "informativo", f"{c.host}:{c.puerto}: {type(e).__name__}", "", REFS))
                continue
            if ident is not None:
                _incorporar(servidores, c, ident, fuente, tabla)
            elif not any(s.puerto == c.puerto for s in servidores):
                servidor = limpiar(cliente.head("/").cabeceras.get("server", ""), 60)
                h.append(Hallazgo(
                    MODULO, "H2-ID-OTRO", "Servicio en escucha sin identificar", Severidad.INFO, "informativo",
                    f"{c.host}:{c.puerto} acepta conexiones, pero ni los perfiles ni Julius lo reconocen"
                    + (f"; Server: {servidor}" if servidor else ""),
                    "Comprueba qué servicio es y si debe estar en este host.", REFS))

    def _identificar_candidato(self, candidato, cliente, objetivo, h):
        """Perfiles específicos, después Julius y por último el genérico: si el genérico fuera
        antes, cualquier servidor con API de OpenAI taparía lo que Julius sabe distinguir."""
        for perfil in PERFILES:
            ident = perfil.identificar_http(cliente)
            if ident is not None:
                return ident, "http"
        ident = self._julius(candidato, objetivo, h)
        if ident is not None:
            return ident, "julius"
        return GENERICO.identificar_http(cliente), "http"

    def _julius(self, candidato, objetivo, h):
        det = herramientas.detectar(JULIUS, objetivo.get("herramientas") or {})
        if not det.disponible:
            if not self._julius_avisada:
                self._julius_avisada = True
                h.append(Hallazgo(
                    MODULO, "H2-ID-JULIUS-NO-INSTALADA", "Julius no está instalada", Severidad.INFO,
                    "informativo", det.error or "",
                    f"Instálala para reconocer más servicios: {JULIUS.instalar_con}", REFS))
            return None
        orden = [det.ruta, "probe", "-o", "json", "-p", str(DIR_SONDAS), "-t", "3", "-c", "4", "--no-color", "-q"]
        if candidato.prefijo:
            orden += ["--base-paths", candidato.prefijo]
        # Sin esquema explícito Julius usaría https y agotaría el tiempo contra un puerto HTTP.
        orden.append(candidato.raiz)
        entorno = {k: v for k, v in os.environ.items() if k.lower() not in _VARIABLES_PROXY}
        resultado = herramientas.ejecutar(orden, timeout=TIMEOUT_JULIUS, env=entorno)
        return interpretar_julius(resultado.stdout) if resultado.returncode == 0 else None

    # ------------------------------------------------------------ declaraciones
    def _aplicar_declaraciones(self, objetivo, destino, servidores, h):
        forzado = _tipo_normalizado(self.servidor_forzado)
        declarado = _tipo_normalizado(objetivo.get("servidor"))
        if destino.puerto is not None:
            servidor = next((s for s in servidores if s.puerto == destino.puerto), None)
        elif forzado is not None or len(servidores) == 1:
            servidor = next(iter(servidores), None)
        else:
            servidor = None
        if forzado is not None:
            self._aplicar_forzado(forzado, destino, servidor, servidores, h)
        elif declarado is not None:
            self._aplicar_declarado(declarado, destino, servidor, servidores, h)

    @staticmethod
    def _aplicar_forzado(forzado, destino, servidor, servidores, h):
        if servidor is None:
            servidores.append(ServidorDetectado(
                tipo=forzado, host=destino.host, puerto=destino.puerto, esquema=destino.esquema,
                prefijo=destino.prefijo, confianza="alta", fuentes=["forzado"]))
            return
        if servidor.tipo not in (forzado, GENERICO.id):
            h.append(_conflicto(f"forzado: {forzado}; detectado: {servidor.tipo} en {_direccion(servidor)}. "
                                "Se usa lo forzado."))
        servidor.tipo, servidor.confianza = forzado, "alta"
        servidor.fuentes.insert(0, "forzado")

    @staticmethod
    def _aplicar_declarado(declarado, destino, servidor, servidores, h):
        if servidor is None:
            if destino.puerto is None and servidores:
                if declarado not in {s.tipo for s in servidores}:
                    h.append(_conflicto(f"declarado: {declarado}; detectado: "
                                        + ", ".join(sorted({s.tipo for s in servidores})) + ". Se usa lo detectado."))
                return
            servidores.append(ServidorDetectado(
                tipo=declarado, host=destino.host, puerto=destino.puerto, esquema=destino.esquema,
                prefijo=destino.prefijo, confianza="baja", fuentes=["declarado"]))
            return
        if servidor.tipo == GENERICO.id:
            servidor.tipo = declarado       # «compatible con OpenAI» no contradice nada: se concreta
        elif servidor.tipo != declarado:
            h.append(_conflicto(f"declarado: {declarado}; detectado: {servidor.tipo} en {_direccion(servidor)}. "
                                "Se usa lo detectado."))
            return
        servidor.fuentes.append("declarado")

    # ---------------------------------------------------------------- informe
    @staticmethod
    def _informar(destino, servidores, procedencia, omision, cerrados, h):
        detectados = [s for s in servidores if not _solo_declarado(s)]
        h.extend(_hallazgo_servidor(s) for s in detectados)
        if not detectados:
            motivos = [procedencia]
            if omision:
                motivos.append("no se ha preguntado por red")
            elif cerrados:
                motivos.append("puertos cerrados: " + ", ".join(str(p) for p in cerrados))
            if servidores:
                motivos.append(f"queda lo declarado sin confirmar: {servidores[0].tipo}")
            h.append(Hallazgo(
                MODULO, "H2-ID-SIN-SERVIDOR", "No se ha identificado ningún servidor LLM", Severidad.INFO,
                "informativo", "; ".join(motivos),
                "Esto no demuestra que no haya ninguno: comprueba que el servidor esté arrancado"
                + (" y habilita el sondeo activo." if omision else " y que el objetivo apunte a su puerto."), REFS))
        elif destino.puerto in cerrados and not any(s.puerto == destino.puerto for s in detectados):
            h.append(Hallazgo(
                MODULO, "H2-ID-SIN-SERVIDOR", "No hay servidor en el endpoint declarado", Severidad.INFO,
                "informativo", f"{destino.host}:{destino.puerto} cerrado; hay servidores en otros puertos",
                "Revisa si el objetivo apunta al puerto correcto.", REFS))
