"""Pruebas de `procesos.py`: troceado de líneas de Windows, interpretación de la salida de
PowerShell y lectura de un /proc de mentira en un directorio temporal."""
import json
import subprocess

import pytest

from mrrobotia import procesos
from mrrobotia.procesos import Proceso, entorno_legible, leer_entorno, procesos_desde_json, trocear_linea_windows


# ------------------------------------------------------------ línea de órdenes
@pytest.mark.parametrize("linea,esperado", [
    (r"C:\srv\llama-server.exe -m C:\m\a.gguf --port 8080",
     [r"C:\srv\llama-server.exe", "-m", r"C:\m\a.gguf", "--port", "8080"]),
    (r'"C:\Program Files\x\llama-server.exe" -m "C:\mis modelos\a b.gguf"',
     [r"C:\Program Files\x\llama-server.exe", "-m", r"C:\mis modelos\a b.gguf"]),
    (r'x.exe "a\"b" c\\d', ["x.exe", 'a"b', r"c\\d"]),
    (r'x.exe "a\\" b', ["x.exe", "a\\", "b"]),
    ('x.exe "a""b"', ["x.exe", 'a"b']),
    ('x.exe ""', ["x.exe", ""]),
    ('  x.exe   a\tb  ', ["x.exe", "a", "b"]),
    ("", []),
    ("   ", []),
])
def test_trocear_linea_windows(linea, esperado):
    assert trocear_linea_windows(linea) == esperado


@pytest.mark.parametrize("args", [
    ["prog", "a b", 'c"d', "e\\", "f\\\\g", 'h\\"i', "", "--clave=un valor"],
    ["prog", r"C:\ruta con espacios\fichero.gguf", "--host", "0.0.0.0"],
])
def test_trocear_es_inversa_de_list2cmdline(args):
    assert trocear_linea_windows(subprocess.list2cmdline(args)) == args


def test_argv_no_aparece_en_repr():
    p = Proceso(1, "x", ["x", "--api-key", "canario-secreto"])
    assert "canario-secreto" not in repr(p)


# -------------------------------------------------------------------- PowerShell
def _salida(datos):
    return json.dumps(datos, ensure_ascii=False).encode("utf-8")


def test_json_con_varios_procesos():
    lista = procesos_desde_json(_salida([
        {"ProcessId": 10, "Name": "a.exe", "CommandLine": r"C:\a.exe --x 1"},
        {"ProcessId": 11, "Name": "b.exe", "CommandLine": "b.exe"},
    ]))
    assert [(p.pid, p.nombre) for p in lista] == [(10, "a.exe"), (11, "b.exe")]
    assert lista[0].argv == [r"C:\a.exe", "--x", "1"]


def test_json_con_un_solo_proceso_es_un_objeto():
    assert [p.pid for p in procesos_desde_json(_salida({"ProcessId": 7, "Name": "a", "CommandLine": "a"}))] == [7]


def test_linea_nula_deja_solo_el_nombre():
    lista = procesos_desde_json(_salida([{"ProcessId": 5, "Name": "llama-server.exe", "CommandLine": None}]))
    assert lista[0].argv == ["llama-server.exe"]


def test_json_con_bom_y_sin_utf8():
    con_bom = b"\xef\xbb\xbf" + _salida({"ProcessId": 1, "Name": "a", "CommandLine": "a"})
    assert len(procesos_desde_json(con_bom)) == 1
    cp850 = '{"ProcessId":2,"Name":"a","CommandLine":"a ñandú"}'.encode("cp850")
    assert len(procesos_desde_json(cp850)) == 1


@pytest.mark.parametrize("salida", [b"", b"no es json", b"42", b'[{"Name":"sin pid"}]', b"[1,2]"])
def test_json_inservible_da_lista_vacia(salida):
    assert procesos_desde_json(salida) == []


def test_enumerar_nunca_lanza(monkeypatch):
    def falla(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 1)

    monkeypatch.setattr(procesos, "enumerar_windows", falla)
    monkeypatch.setattr(procesos, "enumerar_linux", falla)
    assert procesos.enumerar() == []


def test_enumerar_windows_sin_shell(monkeypatch):
    visto = {}

    def falso_run(orden, **kwargs):
        visto.update(orden=orden, kwargs=kwargs)
        return subprocess.CompletedProcess(orden, 0, _salida({"ProcessId": 1, "Name": "a", "CommandLine": "a"}), b"")

    monkeypatch.setattr(procesos.subprocess, "run", falso_run)
    assert len(procesos.enumerar_windows()) == 1
    assert isinstance(visto["orden"], list) and "shell" not in visto["kwargs"] and "text" not in visto["kwargs"]


# ------------------------------------------------------------------- Linux (/proc)
def _proceso_falso(raiz, pid, cmdline=None, environ=None):
    carpeta = raiz / str(pid)
    carpeta.mkdir()
    if cmdline is not None:
        (carpeta / "cmdline").write_bytes(cmdline)
    if environ is not None:
        (carpeta / "environ").write_bytes(environ)


def test_enumerar_linux(tmp_path):
    _proceso_falso(tmp_path, 100, b"/usr/bin/llama-server\0--port\x008080\0")
    _proceso_falso(tmp_path, 2, b"")                              # hilo del núcleo
    _proceso_falso(tmp_path, 300)                                 # sin permiso
    _proceso_falso(tmp_path, 400, b"VLLM::EngineCore_DP0   \0\0\0")   # título de setproctitle
    (tmp_path / "version").write_text("no es un pid")
    lista = sorted(procesos.enumerar_linux(str(tmp_path)), key=lambda p: p.pid)
    assert [p.pid for p in lista] == [100, 400]
    assert lista[0].argv == ["/usr/bin/llama-server", "--port", "8080"]
    assert lista[0].nombre == "llama-server"
    assert lista[1].argv == ["VLLM::EngineCore_DP0"]


def test_leer_entorno_solo_lista_blanca_y_secretos_a_true(tmp_path):
    _proceso_falso(tmp_path, 9, environ=b"LLAMA_API_KEY=canario\0LLAMA_ARG_PORT=8080\0OTRA=no-guardar\0RARA\0")
    entorno = leer_entorno(9, {"LLAMA_API_KEY": True, "LLAMA_ARG_PORT": False, "AUSENTE": False}, str(tmp_path))
    assert entorno == {"LLAMA_API_KEY": True, "LLAMA_ARG_PORT": "8080"}


def test_leer_entorno_no_legible(tmp_path):
    assert leer_entorno(12345, {"X": False}, str(tmp_path)) == {}
    assert leer_entorno("no-es-pid", {"X": False}, str(tmp_path)) == {}


def test_entorno_legible(tmp_path):
    (tmp_path / "9").mkdir()
    (tmp_path / "9" / "environ").write_bytes(b"")
    assert entorno_legible(9, str(tmp_path)) is True
    assert entorno_legible(12345, str(tmp_path)) is False
    assert entorno_legible("no-es-pid", str(tmp_path)) is False


# ------------------------------------------------- árbol de procesos y versión local
def test_enumerar_linux_lee_el_padre(tmp_path):
    _proceso_falso(tmp_path, 10, b"vllm\0serve\0")
    (tmp_path / "10" / "stat").write_bytes(b"10 (vllm (raro) x) S 1 10 10 0")
    _proceso_falso(tmp_path, 11, b"VLLM::EngineCore\0")
    (tmp_path / "11" / "stat").write_bytes(b"11 (VLLM::EngineCore) S 10 10 10 0")
    _proceso_falso(tmp_path, 12, b"otro\0")                     # sin stat legible
    padres = {p.pid: p.ppid for p in procesos.enumerar_linux(str(tmp_path))}
    assert padres == {10: 1, 11: 10, 12: None}


def test_json_de_windows_trae_el_padre():
    lista = procesos_desde_json(_salida([{"ProcessId": 7, "ParentProcessId": 3, "Name": "a", "CommandLine": "a"},
                                         {"ProcessId": 8, "Name": "b", "CommandLine": "b"}]))
    assert [p.ppid for p in lista] == [3, None]


def test_descendientes_recorre_el_arbol_y_aguanta_ciclos():
    lista = [Proceso(1, "a", ["a"], 0), Proceso(2, "b", ["b"], 1), Proceso(3, "c", ["c"], 2), Proceso(4, "d", ["d"], 9),
             Proceso(5, "e", ["e"], 6), Proceso(6, "f", ["f"], 5)]            # 5 y 6 se señalan entre sí
    assert procesos.descendientes(lista, 1) == {2, 3}
    assert procesos.descendientes(lista, 5) == {6}


def venv_falso(raiz, version="0.33.0+cpu", paquete="vllm"):
    sitio = raiz / "lib" / "python3.12" / "site-packages"
    (sitio / f"{paquete}-{version}.dist-info").mkdir(parents=True)
    (sitio / f"{paquete}-{version}.dist-info" / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {paquete}\nVersion: {version}\n", encoding="utf-8")
    (raiz / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (raiz / "bin").mkdir()
    return str(raiz / "bin" / "python")


def test_version_de_paquete_desde_los_metadatos_del_entorno(tmp_path):
    python = venv_falso(tmp_path)
    assert procesos.version_de_paquete(python, "vllm") == "0.33.0+cpu"
    assert procesos.version_de_paquete(python, "otro") is None


@pytest.mark.parametrize("ruta", ["python", "/no/existe/bin/python", "vllm"])
def test_version_de_paquete_sin_entorno_es_none(ruta):
    assert procesos.version_de_paquete(ruta, "vllm") is None


def test_version_de_paquete_fuera_de_un_entorno_virtual(tmp_path):
    venv_falso(tmp_path)
    (tmp_path / "pyvenv.cfg").unlink()
    assert procesos.version_de_paquete(str(tmp_path / "bin" / "python"), "vllm") is None
