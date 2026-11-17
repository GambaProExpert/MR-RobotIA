"""
Núcleo de MRRobotIA: auditor de postura DEFENSIVA para despliegues locales de LLM.

Principios de diseño (citar en la memoria del TFG):
- Solo se audita infraestructura propia o con autorización escrita. El fichero de
  objetivo declara esa autorización y, sin ella, la herramienta no se ejecuta.
- Lectura por defecto. Un módulo "activo" (que interactúa con el servicio) solo
  corre con permiso explícito en el objetivo Y en la línea de órdenes.
- Todo hallazgo es evidencia reproducible, con severidad y referencia a los marcos
  (OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI 600-1).
"""
from __future__ import annotations

import copy
import json
import platform
import re
import socket
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path

from mrrobotia.contexto import texto_enlace


class Severidad(IntEnum):
    INFO = 0
    BAJA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4


class ErrorAutorizacion(Exception):
    pass


def ahora():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class Hallazgo:
    modulo: str
    id: str
    titulo: str
    severidad: Severidad
    estado: str                 # "confirmado" | "potencial" | "sin_concluir" | "informativo"
    evidencia: str
    recomendacion: str = ""
    refs: dict = field(default_factory=dict)   # {"owasp": "...", "atlas": "...", "nist": "..."}
    # Datos estructurados opcionales para un informe detallado (p. ej. el barrido de H4). Se omite
    # del JSON si es None, de modo que los demás módulos no cambian.
    detalle: dict | None = None

    def dict(self):
        d = asdict(self)
        d["severidad"] = self.severidad.name
        if d["detalle"] is None:
            del d["detalle"]
        return d


# Claves cuyo valor es un secreto: se enmascaran en cualquier nivel del objetivo antes de volcarlo
# al informe. Las cabeceras (`headers`) se enmascaran enteras y las plantillas de petición
# (`req_template*`) no se muestran. El nombre de una variable de entorno (`api_key_env`) no es un
# secreto y se conserva.
_CLAVES_SECRETAS = {"api_key", "key", "token", "secret", "password", "passphrase"}
_RE_USUARIO_URL = re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+@")


def _es_clave_secreta(clave):
    k = str(clave).lower()
    return k in _CLAVES_SECRETAS or k.startswith("client_key")


def redactar(valor):
    """Copia de `valor` (el objetivo, por ejemplo) con los secretos enmascarados con '***'. No
    modifica el original. Es la única vía por la que el objetivo llega al informe."""
    if isinstance(valor, dict):
        salida = {}
        for k, v in valor.items():
            kl = str(k).lower()
            if _es_clave_secreta(k) and v is not None:
                salida[k] = "***"
            elif kl == "headers":
                salida[k] = {h: "***" for h in v} if isinstance(v, dict) else "***"
            elif kl.startswith("req_template") and v is not None:
                salida[k] = "<plantilla>"
            else:
                salida[k] = redactar(v)
        return salida
    if isinstance(valor, list):
        return [redactar(v) for v in valor]
    if isinstance(valor, str):
        return _RE_USUARIO_URL.sub("***@", valor)
    return copy.deepcopy(valor)


def cargar_objetivo(ruta):
    """Carga el fichero de alcance y verifica la autorización. Deniega por defecto."""
    objetivo = json.loads(Path(ruta).read_text(encoding="utf-8-sig"))
    aut = objetivo.get("authorization", {})
    if aut.get("authorized") is not True:
        raise ErrorAutorizacion(
            "El objetivo debe declarar authorization.authorized = true. "
            "MRRobotIA solo audita sistemas propios o con permiso escrito.")
    for campo in ("authorized_by", "scope", "date"):
        if not aut.get(campo):
            raise ErrorAutorizacion(f"Falta authorization.{campo} en el objetivo.")
    host = objetivo.get("host", "127.0.0.1")
    if host not in ("127.0.0.1", "localhost", "::1") and aut.get("confirm_non_local") is not True:
        raise ErrorAutorizacion(
            f"El host '{host}' no es local. Marca authorization.confirm_non_local = true "
            "solo si tienes permiso escrito para auditarlo.")
    return objetivo


class Modulo:
    """Base de un módulo de auditoría. Un módulo activo interactúa con el servicio."""
    nombre = "M?"
    titulo = ""
    activo = False
    # El CLI lo pone a True cuando el sondeo activo está autorizado (bandera
    # --active + allow_active en el objetivo). Los módulos híbridos
    # lo leen para decidir si hacen comprobaciones activas.
    activos_ok = False
    etiqueta_escaneo = ""      # etiqueta para el selector --scan del CLI (la fija cada módulo)
    # Para --list: qué hace, si es "pasivo", "hibrido" o "activo", y qué herramienta externa
    # usa (una `herramientas.Herramienta`, o None).
    descripcion = ""
    tipo = "pasivo"
    externa = None
    # True: solo tiene sentido en una máquina con un servidor llama.cpp o vLLM (análisis del
    # host). El CLI lo omite, dejando una nota, si el contexto no contiene ninguno.
    requiere_servidor = False
    # Qué se ha identificado antes de auditar (contexto.Contexto); lo fija el CLI.
    contexto = None
    # False: el módulo no entra en `all` y solo corre si se pide por su etiqueta (p. ej. -s garak),
    # por ser largo o intrusivo.
    en_all = True
    # Carpeta (pathlib.Path) donde el módulo puede dejar sus ficheros; la fija el CLI a partir del
    # prefijo de -o (`<prefijo>_<etiqueta>`). None si el módulo se usa suelto.
    directorio_salida = None

    def ejecutar(self, objetivo) -> list[Hallazgo]:
        raise NotImplementedError

    def motivo_omision_activa(self, objetivo, local):
        """Por qué no se puede sondear por red, o None si se puede: hace falta el doble
        consentimiento y, si el host auditado no es este equipo, confirm_non_local."""
        if not local and objetivo.get("authorization", {}).get("confirm_non_local") is not True:
            return "host no local sin confirm_non_local"
        if not self.activos_ok:
            return "requiere --active y allow_active=true"
        return None

    def hallazgo_sin_contexto(self):
        """Lo que devuelve un módulo que depende de la identificación si se usa suelto."""
        return Hallazgo(
            self.nombre, f"{self.nombre}-SIN-CONTEXTO", "Sin identificación previa del servidor",
            Severidad.INFO, "informativo", "el módulo no ha recibido el contexto de H2-ID",
            "Ejecuta MRRobotIA desde su línea de órdenes: identifica el servidor antes que nada.")


# Estados que el informe en Markdown señala junto al título.
_MARCA_ESTADO = {"potencial": " *(potencial)*", "sin_concluir": " *(sin concluir)*"}


def _celda(valor):
    """Texto apto para una celda de Markdown: una línea y sin separadores de columna."""
    return " ".join(str(valor).split()).replace("|", "\\|")


def _en_linea(valor):
    """Texto para un código en línea de Markdown: una línea y sin comillas inversas."""
    return " ".join(str(valor or "").split()).replace("`", "'")


def _pct(tasa):
    """Porcentaje legible de una tasa 0..1 (sin decimales salvo por debajo del 1 %)."""
    p = tasa * 100
    return f"{p:.0f}" if p >= 1 or p == 0 else f"{p:.1f}"


def _valores(mapa):
    """`clave=valor` de opciones o variables. True (un secreto o una bandera) se muestra como
    presente, y False como no."""
    return ", ".join(f"{k}={'presente' if v is True else 'no' if v is False else _celda(v)}"
                     for k, v in mapa.items())


class Informe:
    def __init__(self, objetivo):
        self.objetivo = objetivo
        self.generado = ahora()
        self.hallazgos: list[Hallazgo] = []
        self.modulos_ejecutados: list[str] = []
        self.notas: list[str] = []
        self.contexto = None       # contexto.Contexto de la identificación, si la hubo
        self.pedidos: list[str] = []          # etiquetas de los escaneos pedidos
        self.omitidos: list[dict] = []        # escaneos que no corrieron: modulo, etiqueta, motivo

    def anadir(self, hallazgos):
        self.hallazgos.extend(hallazgos)

    def omitir(self, modulo, motivo):
        """Anota que un escaneo no se ha ejecutado y por qué."""
        self.omitidos.append({"modulo": modulo.nombre, "etiqueta": modulo.etiqueta_escaneo, "motivo": motivo})

    def _ordenados(self):
        return sorted(self.hallazgos, key=lambda h: -h.severidad)

    def _seccion_contexto(self):
        """Líneas de Markdown de «Qué se ha identificado»."""
        ctx = self.contexto
        if ctx is None:
            return []
        L = ["", "## Qué se ha identificado", "",
             f"- Sistema operativo: {ctx.so}{' (WSL)' if ctx.wsl else ''}"]
        if not ctx.servidores:
            return L + ["- Servidores: no se ha identificado ninguno"]
        L += ["", "| Servidor | Versión | Dirección | Enlace | Autenticación | Confianza | Fuentes | Modelos |",
              "|---|---|---|---|---|---|---|---|"]
        arranques = []
        for s in ctx.servidores:
            puerto = s.puerto if s.puerto is not None else "?"
            direccion = f"{s.esquema}://{s.host}:{puerto}{s.prefijo}"
            L.append(f"| {_celda(s.tipo)} | {_celda(s.version or 'desconocida')} | {_celda(direccion)} | "
                     f"{_celda(texto_enlace(s.enlace))} | {_celda(s.autenticacion or 'sin comprobar')} | "
                     f"{_celda(s.confianza)} | {_celda(', '.join(s.fuentes))} | {_celda(', '.join(s.modelos) or '—')} |")
            detalle = "; ".join(t for t in (_valores(s.opciones), _valores(s.entorno)) if t)
            if detalle:
                arranques.append(f"- {_celda(s.tipo)} en {_celda(direccion)}: {detalle}")
        if arranques:
            L += ["", "Cómo se arrancó:", ""] + arranques
        return L

    def _seccion_garak(self):
        """Líneas de Markdown de «Barrido garak (H4)»: solo si algún hallazgo trae `detalle` de garak.
        Los textos de ejemplo ya vienen truncados y saneados del módulo; aquí solo se evita que
        rompan la tabla o los códigos en línea."""
        sondas = [h for h in self.hallazgos if (h.detalle or {}).get("seccion") == "garak"
                  and h.detalle.get("tipo") == "sonda"]
        resumen = [h for h in self.hallazgos if (h.detalle or {}).get("seccion") == "garak"
                   and h.detalle.get("tipo") == "resumen"]
        if not sondas and not resumen:
            return []
        L = ["", "## Barrido garak (H4)", ""]
        for h in resumen:
            d = h.detalle
            L.append(_celda(d.get("cabecera", "")))
            L.append("")
        if sondas:
            orden = sorted(sondas, key=lambda h: (-h.severidad, -h.detalle.get("tasa", 0)))
            L += ["| Sonda | Fallos | Tasa | OWASP 2025 | Severidad |", "|---|---|---|---|---|"]
            for h in orden:
                d = h.detalle
                L.append(f"| {_celda(d['sonda'])} | {d['fallos']}/{d['total']} | {_pct(d['tasa'])} % | "
                         f"{_celda(d.get('owasp') or '—')} | {h.severidad.name} |")
            L.append("")
        for h in resumen:
            superadas = h.detalle.get("superadas") or []
            if superadas:
                L += [f"Superadas sin fallos: {_celda(', '.join(superadas))}", ""]
            if h.detalle.get("aviso_raw"):
                L += [f"> {_celda(h.detalle['aviso_raw'])}", ""]
        for h in (orden if sondas else []):
            d = h.detalle
            L.append(f"### {_celda(d['sonda'])} — {_pct(d['tasa'])} % ({d['fallos']}/{d['total']})")
            if d.get("objetivo_sonda"):
                L.append(f"Objetivo de la sonda: {_celda(d['objetivo_sonda'])}")
            if d.get("ejemplos"):
                L += ["> Aviso: ejemplos reales de ataque y respuesta del modelo; pueden contener contenido "
                      "ofensivo o peligroso."]
                for i, e in enumerate(d["ejemplos"], 1):
                    L.append(f"{i}. Entrada: `{_en_linea(e.get('entrada'))}`")
                    L.append(f"   Respuesta: `{_en_linea(e.get('salida'))}`")
            if d.get("ruta_hitlog"):
                L.append(f"Registro completo: `{_en_linea(d['ruta_hitlog'])}`")
            L.append("")
        return L

    def to_json(self):
        return json.dumps({
            "herramienta": "MRRobotIA",
            "generado": self.generado,
            "host_auditor": socket.gethostname(),
            "so": platform.platform(),
            "objetivo": redactar({k: v for k, v in self.objetivo.items() if k != "authorization"}),
            "autorizado_por": self.objetivo["authorization"]["authorized_by"],
            "modulos": self.modulos_ejecutados,
            "notas": self.notas,
            "escaneos": {"pedidos": self.pedidos, "omitidos": self.omitidos},
            "contexto": self.contexto.dict() if self.contexto is not None else None,
            "hallazgos": [h.dict() for h in self._ordenados()],
        }, ensure_ascii=False, indent=2)

    def to_markdown(self):
        aut = self.objetivo["authorization"]
        L = [f"# Informe MRRobotIA — {self.objetivo.get('name', 'objetivo')}", "",
             f"- Generado: {self.generado}",
             f"- Autorizado por: {aut['authorized_by']}",
             f"- Ámbito: {aut['scope']}",
             f"- Módulos ejecutados: {', '.join(self.modulos_ejecutados) or '—'}"]
        if self.pedidos:
            L.append(f"- Escaneos pedidos: {', '.join(self.pedidos)}")
        L.append("")
        c = Counter(h.severidad.name for h in self.hallazgos)
        resumen = ", ".join(f"{c[s]} {s}" for s in ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFO") if c[s])
        L.append(f"**Resumen:** {resumen or 'sin hallazgos'}")
        if self.notas:
            L += ["", "**Notas:**"] + [f"- {n}" for n in self.notas]
        if self.omitidos:
            L += ["", "**Escaneos omitidos:**"]
            L += [f"- {o['etiqueta']} ({o['modulo']}): {o['motivo']}" for o in self.omitidos]
        L += self._seccion_contexto()
        L += ["", "| Severidad | Módulo | Hallazgo | Evidencia | Marcos |", "|---|---|---|---|---|"]
        for h in self._ordenados():
            refs = " · ".join(f"{k}:{v}" for k, v in h.refs.items())
            titulo = h.titulo + _MARCA_ESTADO.get(h.estado, "")
            L.append(f"| {h.severidad.name} | {h.modulo} | {titulo} | {h.evidencia} | {refs} |")
        recs = [h for h in self._ordenados() if h.recomendacion]
        if recs:
            L += ["", "## Recomendaciones", ""]
            L += [f"- **[{h.severidad.name}] {h.titulo}** — {h.recomendacion}" for h in recs]
        L += self._seccion_garak()
        return "\n".join(L) + "\n"
