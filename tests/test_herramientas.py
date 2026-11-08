"""Pruebas del núcleo orquestador de herramientas externas (`herramientas.py`).

NO requieren ninguna herramienta de seguridad instalada: usan el propio intérprete
de Python (`sys.executable`) como "binario externo" de prueba, con overrides de ruta.
Así se verifica el andamiaje (detección, ejecución, timeout, versión y el patrón de
`ModuloHerramienta`) de forma reproducible y offline.
"""
import sys

from mrrobotia.herramientas import (
    Herramienta, detectar, ejecutar, _version_menor, ModuloHerramienta,
)
from mrrobotia.nucleo import Hallazgo, Severidad


def test_detectar_con_override_a_python():
    """Con un override de ruta al propio Python, se detecta disponible y con versión."""
    H = Herramienta("py", "python")
    det = detectar(H, overrides={"py": {"ruta": sys.executable}})
    assert det.disponible is True
    assert det.ruta == sys.executable
    assert det.version is not None          # 'python --version' imprime 3.x


def test_detectar_binario_inexistente():
    """Un binario que no está en el PATH y sin override se marca como no disponible."""
    H = Herramienta("fantasma", "no_existe_xyz_123")
    det = detectar(H)
    assert det.disponible is False
    assert det.ruta is None
    assert det.version is None


def test_ejecutar_ok():
    """Un proceso que termina bien devuelve returncode 0 y su stdout capturado."""
    res = ejecutar([sys.executable, "-c", "print('ok')"])
    assert res.returncode == 0
    assert res.expiro is False
    assert "ok" in res.stdout


def test_ejecutar_timeout():
    """Si el proceso excede el timeout, se marca expiro=True sin propagar excepción."""
    res = ejecutar([sys.executable, "-c", "import time;time.sleep(5)"], timeout=1)
    assert res.expiro is True
    assert res.returncode is None


def test_version_menor():
    """Comparación de versiones por tuplas de int (1.2.0 < 1.10.0; 2.0 no < 1.9)."""
    assert _version_menor("1.2.0", "1.10.0") is True
    assert _version_menor("2.0", "1.9") is False


# --- Subclases de prueba: ejercitan el patrón de ModuloHerramienta sin red -------

class _Fake(ModuloHerramienta):
    """Herramienta que NO está instalada: debe informar, no reventar."""
    nombre = "MX"
    titulo = "t"
    herramienta = Herramienta("mx", "no_existe_xyz_123", instalar_con="pip install mx")
    activo = False

    def _auditar(self, objetivo, det):
        return []


class _Ok(ModuloHerramienta):
    """Herramienta disponible (Python): el patrón antepone el hallazgo de versión."""
    nombre = "MX"
    titulo = "t"
    herramienta = Herramienta("py", "python")
    activo = False

    def _auditar(self, objetivo, det):
        return [Hallazgo("MX", "MX-TEST", "t", Severidad.INFO, "informativo", "x")]


def test_modulo_herramienta_no_instalada():
    """Sin la herramienta, devuelve exactamente un hallazgo INFO '*-NO-INSTALADA'."""
    hallazgos = _Fake().ejecutar({})
    assert len(hallazgos) == 1
    assert hallazgos[0].id == "MX-NO-INSTALADA"
    assert hallazgos[0].severidad == Severidad.INFO


def test_modulo_herramienta_disponible_antepone_version():
    """Con la herramienta disponible, el primer hallazgo es el de trazabilidad '*-VERSION'."""
    objetivo = {"herramientas": {"py": {"ruta": sys.executable}}}
    hallazgos = _Ok().ejecutar(objetivo)
    assert len(hallazgos) == 2
    assert hallazgos[0].id == "MX-VERSION"
    assert hallazgos[1].id == "MX-TEST"
