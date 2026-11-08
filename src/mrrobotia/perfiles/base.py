"""
Base de los perfiles de servidor: lo que distingue a llama.cpp de vLLM (cómo se reconoce,
qué opciones de arranque importan, qué se puede pedirle sin efectos) vive en un perfil y
no repartido por los módulos.

INVARIANTE DE PRIVACIDAD: las opciones se leen con la lista blanca `Perfil.opciones`. Lo
que no está en la tabla no se guarda, y un secreto se convierte en `True` durante el
análisis, de modo que su valor nunca entra en las estructuras de datos.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from mrrobotia.nucleo import Hallazgo, Severidad
from mrrobotia.red import a_puerto

_RE_VERSION = re.compile(r"[\w.+-]{1,64}")
_RE_NO_SEGURO = re.compile(r"[^\w.+:@ /=~-]")
_RE_CREDENCIAL_URL = re.compile(r"://[^/\s]*@")
_RE_RUTA = re.compile(r"^(?:[A-Za-z]:|[/\\~.]|file:)")
_RE_RUTA_ABSOLUTA = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|~[\\/]|file:)")
_EXTENSIONES_MODELO = (".gguf", ".bin", ".safetensors", ".pt", ".pth")
MAX_TEXTO = 120
MAX_MODELOS = 16

# Módulos a los que pertenecen los hallazgos que construyen los perfiles.
MODULO_EXPOSICION = "H2"
MODULO_ARRANQUE = "H2-ARRANQUE"
# Marcos por tipo de debilidad.
REFS_EXPO = {"owasp": "LLM10", "atlas": "AML.T0049", "nist": "2.9"}      # exposición del servicio
REFS_FUGA = {"owasp": "LLM02", "atlas": "AML.T0057", "nist": "2.4"}      # fuga de prompt/estado
REFS_SECRETOS = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.9"}  # secretos en el arranque o el entorno
REFS_SUPPLY = {"owasp": "LLM03", "atlas": "AML.T0010", "nist": "2.12"}   # versión y avisos publicados
REFS_MODELS = {"owasp": "LLM02", "atlas": "AML.T0025", "nist": "2.4"}    # enumeración y rutas de modelos


def nombre_fichero(ruta):
    """Último componente de una ruta con separadores de Windows o POSIX, venga de donde
    venga el análisis (`os.path` solo entiende los del sistema que ejecuta)."""
    partes = [p for p in re.split(r"[\\/]+", str(ruta).strip()) if p]
    return partes[-1] if partes else ""


def limpiar(valor, maximo=MAX_TEXTO):
    """Texto apto para el informe a partir de un dato que controla el servidor auditado:
    sin caracteres de control ni de marcado y con longitud acotada."""
    return _RE_NO_SEGURO.sub("_", str(valor)).strip()[:maximo]


def version_segura(valor):
    """La versión si tiene forma de versión; None en otro caso (es un dato remoto)."""
    return valor if isinstance(valor, str) and _RE_VERSION.fullmatch(valor) else None


def nombre_modelo(valor):
    """Nombre presentable de un modelo o None. De una ruta queda solo el fichero; un alias
    o un identificador `org/modelo` se conservan."""
    if not isinstance(valor, str):
        return None
    texto = valor.strip()
    if not texto or texto.lower() == "none":
        return None
    if (_RE_RUTA.match(texto) or "\\" in texto or texto.count("/") > 1
            or texto.lower().endswith(_EXTENSIONES_MODELO)):
        texto = nombre_fichero(texto)
    return limpiar(texto) or None


def normalizar_prefijo(valor):
    """Prefijo de ruta con barra inicial y sin barra final; '' si no hay."""
    if not isinstance(valor, str):
        return ""
    prefijo = "/" + valor.strip().strip("/")
    return "" if prefijo == "/" else prefijo


def es_ruta_absoluta(valor):
    """¿Es una ruta absoluta de disco? Un identificador `org/modelo:Q4` no lo es."""
    return isinstance(valor, str) and bool(_RE_RUTA_ABSOLUTA.match(valor.strip()))


def ids_modelos(datos):
    """Identificadores de la respuesta de `/v1/models` (lista de objetos o de cadenas)."""
    lista = datos.get("data") if isinstance(datos, dict) else datos
    if not isinstance(lista, list):
        return []
    ids = []
    for d in lista:
        valor = d.get("id") if isinstance(d, dict) else d
        if isinstance(valor, str) and valor:
            ids.append(valor)
    return ids


# ------------------------------------------------------- hallazgos compartidos
def hallazgo_autenticacion(autenticacion, detalle, expuesto, proxy, consejo):
    """H2-AUTH según lo observado. `detalle` dice qué se ha pedido y qué ha respondido."""
    if autenticacion == "abierta":
        severidad = Severidad.CRITICA if expuesto and not proxy else Severidad.MEDIA
        return Hallazgo(
            MODULO_EXPOSICION, "H2-AUTH", "El servidor responde sin exigir API key", severidad, "confirmado",
            detalle, f"{consejo}; sin clave, cualquiera que alcance el puerto puede usar el modelo (A5).", REFS_EXPO)
    if autenticacion == "activa":
        return Hallazgo(MODULO_EXPOSICION, "H2-AUTH", "El servidor exige API key", Severidad.INFO, "informativo",
                        detalle, "", REFS_EXPO)
    return Hallazgo(
        MODULO_EXPOSICION, "H2-AUTH", "No se pudo determinar si el servidor exige API key", Severidad.INFO,
        "informativo", detalle, "Comprueba a mano si la API exige autenticación: esto no demuestra que esté protegida.",
        REFS_EXPO)


def hallazgo_modelos(ids):
    """H2-MODELS a partir de los identificadores: rutas de disco (MEDIA) o alias (BAJA)."""
    if not ids:
        return None
    if any(es_ruta_absoluta(i) for i in ids):
        return Hallazgo(
            MODULO_EXPOSICION, "H2-MODELS", "El endpoint /v1/models revela rutas de disco de los modelos",
            Severidad.MEDIA, "confirmado", f"{len(ids)} modelo(s); algún id es una ruta absoluta",
            "Expón alias en lugar de rutas en /v1/models: la ruta en disco informa al atacante de la "
            "estructura del despliegue (LLM02).", REFS_MODELS)
    return Hallazgo(
        MODULO_EXPOSICION, "H2-MODELS", "El endpoint /v1/models enumera los modelos servidos", Severidad.BAJA,
        "confirmado", f"{len(ids)} modelo(s) enumerables (ids tipo alias)",
        "Si no es necesario, restringe /v1/models; permite enumerar los modelos disponibles.", REFS_MODELS)


@dataclass(frozen=True)
class Op:
    clave: str                # nombre canónico en ServidorDetectado.opciones
    valor: bool = True        # False = bandera sin valor
    secreto: bool = False     # True = se guarda True, jamás el valor
    es_ruta: bool = False     # True = se guarda solo el nombre del fichero
    fija: object = True       # valor que guarda una bandera


@dataclass
class Identificacion:
    tipo: str
    confianza: str
    version: str | None = None
    autenticacion: str | None = None
    senales: list[str] = field(default_factory=list)
    modelos: list[str] = field(default_factory=list)


class Perfil:
    id = ""
    nombre = ""
    puertos_defecto = ()      # los que se prueban si no hay otra pista
    enlace_defecto = None     # enlace si el proceso no indica --host
    opciones: dict[str, Op] = {}
    variables: dict[str, bool] = {}   # nombre -> ¿secreto?
    variables_clave = ()      # variables cuya presencia activa la autenticación
    post_permitidos = frozenset()
    fichero_cve = None
    clave_version = None      # versión -> valor comparable para `cve.py`; None si no se sabe comparar
    abreviaturas = False      # argparse admite prefijos únicos de las opciones largas

    # ------------------------------------------------------------ proceso local
    def reconoce_proceso(self, argv) -> bool:
        return False

    def _op_de(self, nombre):
        """Entrada de la tabla para una opción; `--a_b` equivale a `--a-b` en ambos servidores."""
        clave = nombre.replace("_", "-") if nombre.startswith("--") else nombre
        op = self.opciones.get(clave)
        if op is None and self.abreviaturas and clave.startswith("--") and len(clave) > 2:
            candidatas = {o for k, o in self.opciones.items() if k.startswith(clave)}
            if len(candidatas) == 1:
                op = candidatas.pop()
        return op

    def _sanear(self, op, valor):
        if op.secreto or _RE_CREDENCIAL_URL.search(valor):
            return True
        return nombre_fichero(valor) if op.es_ruta else valor

    def analizar_argv(self, argv) -> dict:
        """Opciones de la lista blanca presentes en `argv`, saneadas.

        Admite `--opcion valor` y `--opcion=valor`. Si tras una opción con valor viene otra
        de la tabla no se toma como su valor: así un secreto nunca acaba guardado en claro
        como valor de la opción anterior, y un `--hf-token` sin valor no se traga la siguiente.
        """
        resultado = {}
        tokens = [str(t) for t in list(argv or [])[1:]]
        i = 0
        while i < len(tokens):
            token = tokens[i]
            i += 1
            if not token.startswith("-") or token == "-":
                continue
            nombre, igual, en_linea = token.partition("=")
            op = self._op_de(nombre)
            if op is None:
                continue
            if not op.valor:
                resultado[op.clave] = op.fija
            elif igual:
                resultado[op.clave] = self._sanear(op, en_linea)
            elif i < len(tokens) and self._op_de(tokens[i].partition("=")[0]) is None:
                resultado[op.clave] = self._sanear(op, tokens[i])
                i += 1
            elif op.secreto:
                resultado[op.clave] = True
        return resultado

    def puerto_y_host(self, opciones, entorno=None) -> tuple:
        """(host, puerto) declarados en el arranque; None donde no se sepa."""
        return opciones.get("host"), a_puerto(opciones.get("port"))

    def esquema_de(self, opciones, entorno=None) -> str:
        return "http"

    def prefijo_de(self, opciones, entorno=None) -> str:
        return ""

    def modelos_de(self, opciones) -> list:
        return []

    def autenticacion_de(self, opciones, entorno=None):
        """'activa' si el arranque configura una clave; None si no se puede afirmar nada
        (en Windows el entorno del proceso no es legible y la clave podría venir de ahí)."""
        if "api_key" in opciones or "api_key_file" in opciones:
            return "activa"
        if any(v in (entorno or {}) for v in self.variables_clave):
            return "activa"
        return None

    # ----------------------------------------------------------------- red
    def identificar_http(self, cliente) -> Identificacion | None:
        return None

    # --------------------------------------------- comprobaciones por servidor
    def evaluar_arranque(self, servidor, expuesto) -> list:
        return []

    def sondear(self, cliente, servidor, expuesto, proxy) -> list:
        return []

    def componente_en_uso(self, aviso, servidor):
        """¿Usa este servidor el componente del aviso? True, False o None si no se puede saber."""
        return None
