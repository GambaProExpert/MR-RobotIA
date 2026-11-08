"""
H2 — Inventario y exposición de los servidores LLM identificados.

Trabaja por servidor sobre lo que H2-ID ha dejado en `self.contexto`. Lo común a cualquier
servidor (enlace, propietario, puerto, LAN, CORS, `Host`, TLS y severidad compuesta) está en
este módulo; lo específico, en `perfil.sondear`.

Módulo HÍBRIDO: siempre mira el enlace de red y el propietario del proceso, sin tocar el
servicio. La parte activa exige el doble consentimiento y, si el host no es este equipo,
autorizacion.confirmo_no_local (la misma regla que H2-ID, en `Modulo.motivo_omision_activa`).
Solo usa `ClienteHTTP`, que no permite otra cosa que GET, HEAD, OPTIONS y las POST sin efecto
de la lista blanca del perfil. No recibe sondeo HTTP un servidor solo declarado y sin confirmar,
ni uno con el puerto cerrado; sin puerto TCP (socket UNIX, proceso hijo) quedan las pasivas.

`bind_esperado`, `proxy_autenticador` y `api_key_esperada` del objetivo hablan del servidor
declarado: un segundo servidor del mismo host no está tras ese proxy solo porque lo esté el otro.

INVARIANTE DE PRIVACIDAD: la evidencia son estados, recuentos y nombres de fichero. Nunca el
texto de un prompt, una clave, una plantilla de chat o una ruta absoluta.

Atacantes del modelo de amenazas: A5 (exposición en red) y A3 (otros procesos locales).
Marcos: OWASP LLM Top 10 2025 (LLM10, LLM02, LLM03), MITRE ATLAS y NIST AI 600-1.
"""
from __future__ import annotations

from dataclasses import dataclass

from mrrobotia import red
from mrrobotia.contexto import rotular
from mrrobotia.modulos.h2_identificacion import destino_declarado
from mrrobotia.nucleo import Hallazgo, Modulo, Severidad
from mrrobotia.perfiles import perfil_de
from mrrobotia.perfiles.base import MODULO_EXPOSICION as MODULO
from mrrobotia.perfiles.base import REFS_EXPO, limpiar

TIMEOUT_HTTP = 5            # s por petición
BIND_POR_DEFECTO = "127.0.0.1"
# Dominios reservados: nunca resuelven, de modo que la sonda no apunta a nadie.
ORIGEN_EXTERNO = "http://mrrobotia.invalid"
ORIGEN_LOCAL = "http://localhost:3000"
HOST_FALSO = "rebind.mrrobotia.invalid"
# Una ruta de la API común a todos: `OPTIONS` no la ejecuta y `GET` no despierta un servidor dormido.
RUTA_COMUN = "/v1/models"
ESTADOS_DE_RECHAZO = {400, 403, 421}


def _h(id_, titulo, severidad, evidencia, recomendacion="", estado="confirmado"):
    return Hallazgo(MODULO, id_, titulo, severidad, estado, evidencia, recomendacion, REFS_EXPO)


def _info(id_, titulo, evidencia, recomendacion=""):
    return _h(id_, titulo, Severidad.INFO, evidencia, recomendacion, "informativo")


@dataclass
class _Esperado:
    """Lo que el objetivo dice de un servidor. Fuera del declarado, valores por defecto."""
    bind: str = BIND_POR_DEFECTO
    proxy: bool = False
    clave: bool = False


def _esperado(cfg, es_declarado):
    if not es_declarado:
        return _Esperado()
    return _Esperado(cfg.get("bind_esperado") or BIND_POR_DEFECTO, bool(cfg.get("proxy_autenticador")),
                     cfg.get("api_key_esperada") is True)


def _servidor_declarado(servidores, destino):
    """El servidor del puerto del objetivo; sin puerto declarado, el único que haya."""
    if destino.puerto is not None:
        return next((s for s in servidores if s.puerto == destino.puerto), None)
    return servidores[0] if len(servidores) == 1 else None


# ---------------------------------------------------- funciones puras: evaluación
def _evaluar_bind(enlace, bind_esperado, proxy):
    """Enlace real frente al esperado. Fuera de loopback: ALTA, o MEDIA si es lo declarado;
    en loopback cuando se esperaba otra cosa: MEDIA; desconocido: no se afirma nada."""
    if enlace is None:
        return _info("H2-BIND-DESCONOCIDO", "No se pudo determinar el enlace de red del servidor",
                     "sin fila en escucha en la tabla de puertos ni opción de arranque que lo indique",
                     "Comprueba a mano con 'netstat -ano' (Windows) o 'ss -ltnp' (Linux) a qué interfaz enlaza.")
    esperado = red.clasificar_direccion(bind_esperado)
    if enlace == "loopback":
        if esperado == "loopback":
            return _info("H2-BIND", "El servidor LLM escucha solo en loopback", "enlace a loopback (127.0.0.1/::1)")
        return _h("H2-BIND", "El enlace del servidor no coincide con el esperado", Severidad.MEDIA,
                  f"enlace a loopback; bind_esperado declarado = {limpiar(bind_esperado)}",
                  "Revisa el arranque del servidor: el enlace real no coincide con el declarado en el objetivo.")
    pista_proxy = "" if proxy else " (no se declaró proxy autenticador)"
    if enlace == "todas":
        titulo = "El servidor LLM escucha en todas las interfaces de red"
        evidencia = "enlace a todas las interfaces (0.0.0.0/::)"
    else:
        titulo = "El servidor LLM escucha en una interfaz no local"
        evidencia = f"enlace a {limpiar(enlace[1])} (no es loopback)"
    if enlace == esperado:
        return _h("H2-BIND", titulo, Severidad.MEDIA, evidencia + "; coincide con bind_esperado",
                  "La exposición es la declarada: confirma que está protegida (autenticación, TLS, cortafuegos) (A5)."
                  + pista_proxy)
    return _h("H2-BIND", titulo, Severidad.ALTA, evidencia,
              "Enlaza a 127.0.0.1 (--host 127.0.0.1) o ponlo tras un proxy inverso con autenticación: tal como está, "
              "queda accesible desde la red (A5)." + pista_proxy)


def _evaluar_owner(info, pid):
    """`info` es lo que da `red.owner_proceso`. No se vuelca el nombre de usuario."""
    referencia = f"pid {pid}" if pid is not None else "pid desconocido"
    if info is None:
        return _info("H2-OWNER", "No se pudo verificar el usuario del proceso del servidor",
                     f"propietario del proceso no verificable ({referencia})",
                     "Comprueba a mano que el servidor no se ejecuta como root/SYSTEM; usa una cuenta sin privilegios (A3).")
    if info[0]:
        return _h("H2-OWNER", "El servidor LLM se ejecuta con una cuenta privilegiada", Severidad.ALTA,
                  f"proceso ({referencia}) con cuenta privilegiada",
                  "Ejecuta el servidor con una cuenta sin privilegios: si se ve comprometido, limita el impacto (A3).")
    return _info("H2-OWNER", "El servidor LLM se ejecuta con una cuenta sin privilegios",
                 f"proceso ({referencia}) con cuenta sin privilegios")


def _evaluar_cors(externo, local, autenticacion, proxy):
    """Comprobaciones previas CORS con un origen externo y uno local. Si cualquier web puede
    leer las respuestas, la gravedad depende de que la API exija clave. `Access-Control-Allow-Credentials`
    solo llega en `OPTIONS`."""
    if externo.estado is None:
        return _info("H2-CORS", "No se pudo comprobar CORS", f"OPTIONS sin respuesta ({externo.error})",
                     "Comprueba a mano qué orígenes admite: esto no demuestra que esté restringido.")
    permitido = str(externo.cabeceras.get("access-control-allow-origin", "")).strip()
    credenciales = str(externo.cabeceras.get("access-control-allow-credentials", "")).strip().lower() == "true"
    protegido = autenticacion == "activa" or proxy
    if permitido == ORIGEN_EXTERNO or permitido == "*":
        refleja = permitido == ORIGEN_EXTERNO
        if autenticacion == "abierta" and not proxy:
            severidad = Severidad.ALTA
        elif not protegido or (refleja and credenciales):
            severidad = Severidad.MEDIA
        else:
            severidad = Severidad.BAJA
        detalle = "refleja el Origin" if refleja else "Access-Control-Allow-Origin: *"
        return _h("H2-CORS", "CORS permite que cualquier web use el servidor", severidad,
                  f"{detalle} con credenciales={'sí' if credenciales else 'no'}; "
                  f"autenticación: {autenticacion or 'sin comprobar'}",
                  "Fija una lista de orígenes (--cors-origins en llama.cpp): una web maliciosa podría leer las "
                  "respuestas desde el navegador de la víctima (A5).")
    if "," in permitido:
        return _h("H2-CORS", "CORS devuelve una lista de orígenes que los navegadores no aceptan", Severidad.BAJA,
                  "Access-Control-Allow-Origin con varios valores",
                  "Ningún navegador acepta una lista en esa cabecera: usa un único origen.")
    if permitido:
        return _info("H2-CORS", "CORS limitado a un origen fijo", f"Access-Control-Allow-Origin: {limpiar(permitido, 60)}")
    if not 200 <= externo.estado < 300:
        return _info("H2-CORS", "CORS sin concluir", f"OPTIONS respondió {externo.estado}",
                     "Comprueba a mano qué orígenes admite: esto no demuestra que esté restringido.")
    if str(local.cabeceras.get("access-control-allow-origin", "")).strip() == ORIGEN_LOCAL:
        return _info("H2-CORS", "CORS solo admite orígenes locales",
                     "se acepta un origen localhost y se rechaza uno externo")
    return _info("H2-CORS", "CORS no admite orígenes externos", "sin Access-Control-Allow-Origin para un origen externo")


def _evaluar_host(normal, falso, autenticacion, proxy):
    """¿Acepta un `Host` que no es el suyo? Es el otro requisito del DNS rebinding, distinto
    de reflejar `Origin`: con él, una web apunta su dominio a loopback y lee la API."""
    if normal.estado is None or falso.estado is None:
        return _info("H2-HOST", "No se pudo comprobar la cabecera Host", "sin respuesta a la comprobación")
    comparacion = f"Host falso: {falso.estado}; Host real: {normal.estado}"
    if falso.estado in ESTADOS_DE_RECHAZO and normal.estado != falso.estado:
        return _info("H2-HOST", "El servidor rechaza un Host desconocido", comparacion)
    if falso.estado != normal.estado:
        return _info("H2-HOST", "Comprobación de Host sin concluir", comparacion)
    evidencia = f"responde igual con un Host falso ({falso.estado})"
    if autenticacion == "activa" or proxy:
        return _info("H2-HOST", "El servidor no valida la cabecera Host, pero exige autenticación",
                     evidencia, "La autenticación evita el DNS rebinding contra este puerto.")
    if autenticacion == "abierta":
        return _h("H2-HOST", "El servidor no valida la cabecera Host y no exige clave (DNS rebinding)",
                  Severidad.MEDIA, evidencia,
                  "Exige clave de API o pon delante un proxy que valide Host: una web puede apuntar su dominio a esta "
                  "IP y usar la API desde el navegador de la víctima, aun en loopback (A5).")
    return _h("H2-HOST", "El servidor no valida la cabecera Host", Severidad.BAJA, evidencia,
              "Comprueba si exige autenticación: sin ella, sería vulnerable a DNS rebinding (A5).", "potencial")


def _evaluar_tls(esquema, expuesto):
    """HTTP sin TLS: ALTA si está expuesto y BAJA en loopback."""
    if str(esquema).lower() == "https":
        return _info("H2-TLS", "El servidor usa HTTPS", "esquema https")
    return _h("H2-TLS", "El servidor sirve en HTTP sin TLS", Severidad.ALTA if expuesto else Severidad.BAJA,
              "esquema http (sin cifrado en tránsito)",
              "Sirve tras TLS si el servicio sale de loopback; en claro, el tráfico y la API key viajan sin cifrar (A5).")


def _severidad_compuesta(enlace, autenticacion, proxy, expuesto):
    """Resumen de exposición. Un enlace desconocido no se trata como loopback, y una
    autenticación sin determinar no se da por buena."""
    abierta = autenticacion == "abierta"
    if expuesto:
        if abierta and not proxy:
            return _h("H2-EXPOSICION", "Servidor LLM expuesto en red y sin autenticación", Severidad.CRITICA,
                      "accesible desde la red + responde sin API key + sin proxy autenticador",
                      "Enlaza a 127.0.0.1 y exige API key o pon un proxy con autenticación. Tal cual, cualquiera en "
                      "la red puede usar el modelo sin credenciales (A5).")
        matices = []
        if autenticacion == "activa":
            matices.append("con API key")
        elif not abierta:
            matices.append("autenticación sin determinar")
        if proxy:
            matices.append("tras proxy")
        detalle = "accesible desde la red" + (" (" + ", ".join(matices) + ")" if matices else "")
        return _h("H2-EXPOSICION", "Servidor LLM accesible desde la red", Severidad.ALTA, detalle,
                  "Confirma que la exposición es deliberada y que la autenticación es robusta; prefiere 127.0.0.1 si "
                  "no necesitas acceso remoto (A5).")
    if enlace is None:
        if abierta:
            return _h("H2-EXPOSICION", "Servidor LLM sin API key y con enlace de red desconocido", Severidad.MEDIA,
                      "responde sin API key; no se sabe a qué interfaz está enlazado",
                      "Comprueba el enlace y exige API key: si sale de loopback, cualquiera en la red podría usarlo (A5).")
        return _info("H2-EXPOSICION", "Exposición sin determinar", "enlace de red desconocido")
    if abierta:
        return _h("H2-EXPOSICION", "Servidor LLM en loopback sin API key", Severidad.BAJA,
                  "enlace a loopback; responde sin API key (accesible solo localmente)",
                  "Aun en loopback, considera exigir API key para limitar el acceso de otros procesos locales (A3).")
    estado = "exige API key" if autenticacion == "activa" else "autenticación sin determinar"
    return _info("H2-EXPOSICION", "Servidor LLM en loopback", f"enlace a loopback; {estado}")


def _subir_auth_si_se_esperaba_clave(hallazgos, servidor, esperada):
    """Si el objetivo dice que debería tener clave y responde sin ella, no es solo un
    servidor abierto: es un despliegue que no coincide con lo previsto."""
    if not esperada or servidor.autenticacion != "abierta":
        return
    for h in hallazgos:
        if h.id == "H2-AUTH" and h.severidad < Severidad.CRITICA:
            h.severidad = Severidad(h.severidad + 1)
            h.evidencia += "; el objetivo declara api_key_esperada"


# ------------------------------------------------------------------------- módulo
class H2Exposicion(Modulo):
    nombre = MODULO
    titulo = "Inventario y exposición del servidor LLM"
    activo = False      # HÍBRIDO: se ejecuta siempre y autogatea las partes activas
    etiqueta_escaneo = "exposicion"

    def ejecutar(self, objetivo):
        if self.contexto is None:
            return [self.hallazgo_sin_contexto()]
        try:
            return self._auditar_servidores(objetivo)
        except Exception as e:              # invariante: un fallo nunca llega al llamador
            return [_info("H2-ERROR", "Error durante el sondeo de exposición", type(e).__name__,
                          "Revisa la configuración de 'exposicion' en el objetivo.")]

    def _auditar_servidores(self, objetivo):
        cfg = objetivo.get("exposicion") or {}
        destino = destino_declarado(objetivo)
        servidores = self.contexto.servidores
        omision = self.motivo_omision_activa(objetivo, red.es_host_local(destino.host))
        hallazgos = []
        if omision:
            hallazgos.append(_info("H2-ACTIVO-OMITIDO", "Sondeo activo de H2 omitido", omision,
                                   "Sin el sondeo activo solo se comprueban el enlace y el propietario."))
        if not servidores:
            hallazgos.append(_info("H2-SIN-SERVIDOR", "No hay servidores que auditar", "H2-ID no ha identificado ninguno"))
        declarado = _servidor_declarado(servidores, destino)
        for servidor in servidores:
            parciales = []
            try:
                self._auditar(servidor, _esperado(cfg, servidor is declarado), omision, parciales)
            except Exception as e:          # invariante: un fallo nunca llega al llamador
                parciales.append(_info("H2-ERROR", "Error durante el sondeo de exposición", type(e).__name__,
                                       "Revisa el estado del servidor."))
            hallazgos.extend(rotular(parciales, servidor))
        return hallazgos

    def _auditar(self, s, esperado, omision, h):
        """Acumula en `h` para conservar lo parcial si algo falla a mitad."""
        h.append(_evaluar_bind(s.enlace, esperado.bind, esperado.proxy))
        h.append(_evaluar_owner(red.owner_proceso(s.pid), s.pid))
        if s.puerto is None:
            h.append(_info("H2-SIN-PUERTO", "Servidor sin puerto TCP",
                           "socket UNIX o proceso hijo: solo comprobaciones pasivas"))
            return
        if omision:
            return
        abierto = red.sondear(s.host, s.puerto)
        h.append(_info("H2-PORT", "Puerto del servidor " + ("abierto" if abierto else "cerrado"),
                       "abierto" if abierto else "cerrado",
                       "" if abierto else "El servidor no responde en ese puerto; arráncalo o revisa host/puerto."))
        if not abierto:
            return
        expuesto = self._expuesto_en_red(s, h)
        if s.fuentes == ["declarado"]:
            h.append(_info("H2-SIN-CONFIRMAR", "Servidor declarado sin confirmar",
                           "no se ha reconocido en ese puerto: no se le sondea por HTTP",
                           "Comprueba que el objetivo apunte al servicio correcto."))
            return
        self._sondeo_http(s, expuesto, esperado, h)

    @staticmethod
    def _expuesto_en_red(s, h):
        """¿Se puede llegar a él desde fuera de loopback? Si el host auditado no es loopback,
        ya se ha llegado por una dirección de red; si lo es, se prueba la IP de red del equipo."""
        direccion = None
        if isinstance(red.clasificar_direccion(s.host), tuple):
            direccion = s.host
        else:
            ip = red.ip_rutable()
            if ip and red.clasificar_direccion(ip) != "loopback" and red.sondear(ip, s.puerto):
                direccion = ip
        if direccion is not None:
            h.append(_h("H2-LAN", "El servidor responde en una IP de red (accesible desde la LAN)", Severidad.ALTA,
                        f"responde en {limpiar(direccion)}:{s.puerto} (no es loopback)",
                        "Enlaza a 127.0.0.1 o protege el acceso desde la red (cortafuegos, proxy con autenticación) (A5)."))
        return red.es_no_loopback(s.enlace) or direccion is not None

    @staticmethod
    def _sondeo_http(s, expuesto, esperado, h):
        """Primero el perfil: puede concretar la autenticación de la que dependen los demás."""
        perfil = perfil_de(s)
        cliente = red.ClienteHTTP(s.url, timeout=TIMEOUT_HTTP, post_permitidos=perfil.post_permitidos)
        h.extend(perfil.sondear(cliente, s, expuesto, esperado.proxy))
        _subir_auth_si_se_esperaba_clave(h, s, esperado.clave)
        externo = cliente.options(RUTA_COMUN, origin=ORIGEN_EXTERNO)
        h.append(_evaluar_cors(externo, cliente.options(RUTA_COMUN, origin=ORIGEN_LOCAL), s.autenticacion, esperado.proxy))
        h.append(_evaluar_host(cliente.get(RUTA_COMUN), cliente.get(RUTA_COMUN, cabeceras={"Host": HOST_FALSO}),
                               s.autenticacion, esperado.proxy))
        # Sin respuesta HTTP no se ha observado en qué esquema sirve.
        if externo.estado is not None:
            h.append(_evaluar_tls(s.esquema, expuesto))
        h.append(_severidad_compuesta(s.enlace, s.autenticacion, esperado.proxy, expuesto))
