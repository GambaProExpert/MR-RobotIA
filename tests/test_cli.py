"""Pruebas del comando: selector de escaneos (--scan, --skip, --list), --server,
--declared-only, la carpeta de --out, el aislamiento de un módulo que falla y la omisión del
análisis del host cuando no hay servidor LLM. Son herméticas: procesos, tabla de puertos y
herramientas externas están simulados, y no se pregunta por red."""
import json
import sys
import types
from pathlib import Path

import pytest

from mrrobotia import cli, nucleo
from mrrobotia.herramientas import Deteccion
from mrrobotia.modulos import h2_identificacion as h2id
from mrrobotia.modulos.h3_host import H3Host
from mrrobotia.modulos.h3_puertos import H3Puertos
from mrrobotia.modulos.h3_ssh import H3Ssh
from mrrobotia.procesos import Proceso

ETIQUETAS = {"id", "integrity", "config", "exposure", "startup", "cve", "ssh", "ports", "vulns"}


def objetivo(**extra):
    base = {"nombre": "prueba", "host": "127.0.0.1",
            "autorizacion": {"tengo_autorizacion": True, "autorizado_por": "x", "ambito": "x", "fecha": "2026-01-01"}}
    return {**base, **extra}


def proceso_llama(puerto, pid=100):
    return Proceso(pid, "llama-server", ["/opt/llama-server", "-m", "/srv/m/modelo.gguf", "--port", str(puerto)])


@pytest.fixture
def entorno(monkeypatch):
    """Aísla el comando de la máquina real. Devuelve un objeto para configurar el escenario."""
    e = types.SimpleNamespace(procesos=[], instaladas=set())
    monkeypatch.setattr(h2id.procesos, "enumerar", lambda: list(e.procesos))
    monkeypatch.setattr(h2id.red, "tabla_puertos", lambda: "")
    monkeypatch.setattr(h2id.red, "sondear", lambda *a, **k: False)
    monkeypatch.setattr(h2id.red, "ip_rutable", lambda: None)
    monkeypatch.setattr(
        cli.herramientas, "detectar",
        lambda herramienta, overrides=None: Deteccion(herramienta.nombre in e.instaladas, None, None, None))
    return e


class Espia(nucleo.Modulo):
    """Módulo de prueba: anota si se ejecutó y qué contexto recibió."""
    nombre, titulo = "ESPIA", "módulo espía"

    def __init__(self, etiqueta="espia", requiere_servidor=False, falla=None):
        self.etiqueta_escaneo = etiqueta
        self.nombre = f"ESPIA-{etiqueta}"
        self.requiere_servidor = requiere_servidor
        self.falla = falla
        self.ejecuciones = 0

    def ejecutar(self, objetivo):
        self.ejecuciones += 1
        if self.falla:
            raise self.falla
        return []


def lanzar(monkeypatch, tmp_path, obj, *extra, nombre="informe"):
    """Ejecuta el comando y devuelve el JSON del informe."""
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    salida = tmp_path / nombre
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--target", str(ruta), "--out", str(salida), *extra])
    cli.main()
    return json.loads(Path(str(salida) + ".json").read_text(encoding="utf-8"))


def ids(datos):
    return [h["id"] for h in datos["hallazgos"]]


# ------------------------------------------------------------------- --scan y --help
def test_ayuda_se_genera_del_registro(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--help"])
    with pytest.raises(SystemExit) as salida:
        cli.main()
    assert salida.value.code == 0
    texto = " ".join(capsys.readouterr().out.split())
    for etiqueta in ETIQUETAS | {"server", "host", "active", "passive", "all"}:
        assert etiqueta in texto
    for opcion in ("--skip", "--list", "--server", "--declared-only"):
        assert opcion in texto


def test_ayuda_incluye_modulos_nuevos(monkeypatch):
    nuevo = Espia("zeta")
    monkeypatch.setattr(cli, "MODULOS", [*cli.MODULOS, nuevo])
    assert "zeta" in cli._ayuda_escaneo()


def test_grupo_servidor():
    assert cli.GRUPOS["server"] == {"exposure", "startup", "cve"}
    assert cli._resolver_escaneo("server") == ({"exposure", "startup", "cve"}, False)


def test_todas_las_etiquetas_son_validas():
    for etiqueta in ETIQUETAS:
        assert cli._resolver_escaneo(etiqueta) == ({etiqueta}, False)
    assert cli._resolver_escaneo("all") == (None, False)
    assert cli._resolver_escaneo("passive") == (None, True)
    assert cli._resolver_escaneo("host,passive") == ({"ssh", "ports", "vulns"}, True)


@pytest.mark.parametrize("valor", ["foo", "passive,foo", "all,foo"])
def test_escaneo_desconocido(valor):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo(valor)
    assert "--scan: unknown value 'foo'" in str(e.value) and "startup" in str(e.value)


# ---------------------------------------------------------------------------- --skip
def test_excluir_etiqueta_de_todo():
    seleccion, _ = cli._resolver_escaneo("all", "cve")
    assert seleccion == ETIQUETAS - {"cve"}


def test_excluir_un_grupo():
    seleccion, _ = cli._resolver_escaneo("all", "host,server")
    assert seleccion == {"id", "integrity", "config"}


def test_excluir_de_una_seleccion():
    assert cli._resolver_escaneo("server", "cve") == ({"exposure", "startup"}, False)


@pytest.mark.parametrize("excluir", ["id", "cve,id"])
def test_no_se_puede_excluir_la_identificacion(excluir):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo("all", excluir)
    assert "cannot be skipped" in str(e.value) and "id scan" in str(e.value)


@pytest.mark.parametrize("excluir,mensaje", [("foo", "unknown value 'foo'"), ("all", "'all' cannot be skipped"),
                                             ("passive", "'passive' cannot be skipped")])
def test_excluir_invalido(excluir, mensaje):
    with pytest.raises(SystemExit) as e:
        cli._resolver_escaneo("all", excluir)
    assert mensaje in str(e.value)


def test_excluir_de_punta_a_punta(entorno, monkeypatch, tmp_path):
    a, b = Espia("a"), Espia("b")
    monkeypatch.setattr(cli, "MODULOS", [a, b])
    datos = lanzar(monkeypatch, tmp_path, objetivo(), "--skip", "b")
    assert (a.ejecuciones, b.ejecuciones) == (1, 0)
    assert datos["modulos"] == ["H2-ID", "ESPIA-a"]
    assert datos["escaneos"]["pedidos"] == ["id", "a"]
    assert datos["escaneos"]["omitidos"] == [{"modulo": "ESPIA-b", "etiqueta": "b", "motivo": "excluido con --skip"}]


# ----------------------------------------------------------------------------- --list
def test_listar_no_necesita_objetivo(entorno, monkeypatch, capsys):
    entorno.instaladas = {"trivy"}
    monkeypatch.delenv("MRROBOTIA_TARGET", raising=False)
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--list"])
    cli.main()
    salida = capsys.readouterr().out
    for etiqueta in ETIQUETAS:
        assert f"  {etiqueta}  [" in salida
    for modulo in [cli.IDENTIFICACION, *cli.MODULOS]:
        assert f"[{modulo.nombre}]" in salida and modulo.descripcion in salida
    assert "type: hybrid" in salida and "type: passive" in salida
    assert "julius (not installed)" in salida and "ssh-audit (not installed)" in salida
    assert "trivy (installed)" in salida
    assert "server: the LLM server" in salida and "= cve, exposure, startup" in salida
    assert "host: " in salida and "active: " in salida and "passive: " in salida
    assert "cannot be skipped" in salida


def test_cada_modulo_declara_su_descripcion_y_tipo():
    for modulo in [cli.IDENTIFICACION, *cli.MODULOS]:
        assert modulo.descripcion and modulo.tipo in ("pasivo", "hibrido", "activo")
    assert cli.IDENTIFICACION.externa.nombre == "julius"
    assert {m.etiqueta_escaneo: m.externa.nombre for m in cli.MODULOS if m.externa} == {
        "ssh": "ssh-audit", "vulns": "trivy"}


# ---------------------------------------------------------------------------- --server
def test_servidor_forzado_distinto_avisa_del_conflicto(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080)]
    obj = objetivo(endpoint="http://127.0.0.1:8080/v1/chat/completions")
    datos = lanzar(monkeypatch, tmp_path, obj, "--scan", "id", "--server", "vllm")
    assert "H2-ID-CONFLICTO" in ids(datos)
    assert [s["tipo"] for s in datos["contexto"]["servidores"]] == ["vllm"]


def test_servidor_auto_no_fuerza_nada(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080)]
    obj = objetivo(endpoint="http://127.0.0.1:8080/v1/chat/completions")
    datos = lanzar(monkeypatch, tmp_path, obj, "--scan", "id", "--server", "auto")
    assert "H2-ID-CONFLICTO" not in ids(datos)
    assert [s["tipo"] for s in datos["contexto"]["servidores"]] == ["llama.cpp"]


def test_servidor_valor_invalido(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--list", "--server", "ollama"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2 and "invalid choice" in capsys.readouterr().err


def test_servidor_forzado_no_se_arrastra_entre_ejecuciones(entorno, monkeypatch, tmp_path):
    lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080"), "--scan", "id",
           "--server", "vllm")
    datos = lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080"), "--scan", "id")
    assert datos["contexto"]["servidores"] == []


# ----------------------------------------------------------------------- --declared-only
def test_solo_declarado_audita_un_servidor(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080, pid=1), proceso_llama(8081, pid=2)]
    obj = objetivo(endpoint="http://127.0.0.1:8080")
    todos = lanzar(monkeypatch, tmp_path, obj, "--scan", "id")
    assert sorted(s["puerto"] for s in todos["contexto"]["servidores"]) == [8080, 8081]
    datos = lanzar(monkeypatch, tmp_path, obj, "--scan", "id", "--declared-only")
    assert [s["puerto"] for s in datos["contexto"]["servidores"]] == [8080]
    assert any("solo el servidor del endpoint" in n for n in datos["notas"])


def test_solo_declarado_no_prueba_otros_candidatos():
    destino = h2id.destino_declarado(objetivo(endpoint="http://127.0.0.1:8080"))
    assert [c.puerto for c in h2id._candidatos(destino, [], solo_declarado=True)] == [8080]
    assert len(h2id._candidatos(destino, [], solo_declarado=False)) > 1


def test_solo_declarado_sin_servidor_declarado(entorno, monkeypatch, tmp_path):
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo(servidor="llama.cpp")), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--target", str(ruta), "--out", str(tmp_path / "i"),
                                      "--declared-only"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--declared-only" in str(e.value) and "endpoint" in str(e.value)
    assert not (tmp_path / "i.json").exists()


def test_solo_declarado_con_puerto_en_exposicion(entorno, monkeypatch, tmp_path):
    entorno.procesos = [proceso_llama(8080, pid=1), proceso_llama(8081, pid=2)]
    datos = lanzar(monkeypatch, tmp_path, objetivo(exposicion={"puerto": 8081}), "--scan", "id",
                   "--declared-only")
    assert [s["puerto"] for s in datos["contexto"]["servidores"]] == [8081]


# ------------------------------------------------------------ H3 solo con servidor LLM
def test_los_modulos_del_host_requieren_servidor():
    assert H3Ssh.requiere_servidor and H3Puertos.requiere_servidor and H3Host.requiere_servidor
    assert {m.etiqueta_escaneo for m in cli.MODULOS if m.requiere_servidor} == {"ssh", "ports", "vulns"}


def test_host_omitido_sin_servidor(entorno, monkeypatch, tmp_path):
    host, otro = Espia("host", requiere_servidor=True), Espia("otro")
    monkeypatch.setattr(cli, "MODULOS", [host, otro])
    datos = lanzar(monkeypatch, tmp_path, objetivo())
    assert (host.ejecuciones, otro.ejecuciones) == (0, 1)
    assert any("ESPIA-host" in n and "llama.cpp o vLLM" in n and "--server" in n and "'servidor'" in n
               for n in datos["notas"])
    assert datos["escaneos"]["omitidos"][0]["etiqueta"] == "host"
    assert "ESPIA-host" not in datos["modulos"]


@pytest.mark.parametrize("como", ["proceso", "declarado", "forzado"])
def test_host_se_ejecuta_con_servidor(entorno, monkeypatch, tmp_path, como):
    host = Espia("host", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [host])
    obj, extra = objetivo(endpoint="http://127.0.0.1:8080"), []
    if como == "proceso":
        entorno.procesos = [proceso_llama(8080)]
    elif como == "declarado":
        obj["servidor"] = "vllm"
    else:
        extra = ["--server", "llama.cpp"]
    datos = lanzar(monkeypatch, tmp_path, obj, *extra)
    assert host.ejecuciones == 1 and datos["escaneos"]["omitidos"] == []


def test_otro_servicio_no_cuenta_como_servidor_llm(entorno, monkeypatch, tmp_path):
    host = Espia("host", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [host])
    lanzar(monkeypatch, tmp_path, objetivo(endpoint="http://127.0.0.1:8080", servidor="ollama"))
    assert host.ejecuciones == 0


# ----------------------------------------------------------------------------- --out
def test_salida_crea_la_carpeta(entorno, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "MODULOS", [])
    lanzar(monkeypatch, tmp_path, objetivo(), "--scan", "id", nombre="a/b/informe")
    assert (tmp_path / "a" / "b" / "informe.json").exists() and (tmp_path / "a" / "b" / "informe.md").exists()


def test_salida_imposible_falla_antes_de_escanear(entorno, monkeypatch, tmp_path):
    fichero = tmp_path / "fichero"
    fichero.write_text("x", encoding="utf-8")
    espia = Espia()
    monkeypatch.setattr(cli, "MODULOS", [espia])
    monkeypatch.setattr(cli.IDENTIFICACION, "ejecutar", lambda obj: pytest.fail("no debe escanear"))
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--target", str(ruta), "--out", str(fichero / "sub" / "inf")])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--out" in str(e.value) and "Nothing has been scanned" in str(e.value)
    assert espia.ejecuciones == 0


@pytest.mark.parametrize("sufijo", ["/", "\\"])
def test_salida_no_puede_ser_una_carpeta(tmp_path, sufijo):
    with pytest.raises(SystemExit) as e:
        cli._preparar_salida(str(tmp_path) + sufijo)
    assert "prefix" in str(e.value)


def test_salida_con_nombre_de_carpeta_existente(tmp_path):
    (tmp_path / "informe.json").mkdir()
    with pytest.raises(SystemExit) as e:
        cli._preparar_salida(str(tmp_path / "informe"))
    assert "--out" in str(e.value)


# ----------------------------------------------------------- un módulo que falla
def test_un_modulo_que_falla_no_aborta(entorno, monkeypatch, tmp_path):
    malo = Espia("malo", falla=RuntimeError("secreto-en-el-mensaje /ruta/privada"))
    bueno = Espia("bueno")
    monkeypatch.setattr(cli, "MODULOS", [malo, bueno])
    ruta = tmp_path / "objetivo.json"
    ruta.write_text(json.dumps(objetivo()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mrrobotia", "--target", str(ruta), "--out", str(tmp_path / "i")])
    cli.main()
    texto = (tmp_path / "i.json").read_text(encoding="utf-8") + (tmp_path / "i.md").read_text(encoding="utf-8")
    datos = json.loads((tmp_path / "i.json").read_text(encoding="utf-8"))
    error = next(h for h in datos["hallazgos"] if h["id"] == "ESPIA-malo-ERROR")
    assert (error["severidad"], error["estado"], error["evidencia"]) == ("INFO", "sin_concluir", "RuntimeError")
    assert bueno.ejecuciones == 1
    assert "secreto-en-el-mensaje" not in texto and "/ruta/privada" not in texto


def test_la_identificacion_que_falla_no_aborta(entorno, monkeypatch, tmp_path):
    def revienta(obj):
        raise OSError("ruta privada")

    otro = Espia()
    monkeypatch.setattr(cli, "MODULOS", [otro])
    monkeypatch.setattr(cli.IDENTIFICACION, "ejecutar", revienta)
    datos = lanzar(monkeypatch, tmp_path, objetivo())
    assert "H2-ID-ERROR" in ids(datos) and otro.ejecuciones == 1


# ------------------------------------------------------------ qué se pidió y qué se omitió
def test_informe_dice_que_se_pidio_y_que_se_omitio(entorno, monkeypatch, tmp_path):
    a, b, c = Espia("a"), Espia("b"), Espia("c", requiere_servidor=True)
    monkeypatch.setattr(cli, "MODULOS", [a, b, c])
    datos = lanzar(monkeypatch, tmp_path, objetivo(), "--scan", "a,c")
    assert datos["escaneos"]["pedidos"] == ["id", "a", "c"]
    omitidos = {o["etiqueta"]: o["motivo"] for o in datos["escaneos"]["omitidos"]}
    assert omitidos == {"b": "no seleccionado con --scan", "c": "no se ha identificado un servidor llama.cpp ni vLLM"}
    md = (tmp_path / "informe.md").read_text(encoding="utf-8")
    assert "Escaneos pedidos: id, a, c" in md and "- b (ESPIA-b): no seleccionado con --scan" in md


# ------------------------------------------------------------------ errores del objetivo
def test_objetivo_inexistente_o_invalido(monkeypatch, tmp_path):
    for contenido in (None, "{no es json"):
        ruta = tmp_path / "o.json"
        if contenido is not None:
            ruta.write_text(contenido, encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["mrrobotia", "--target", str(ruta), "--out", str(tmp_path / "i")])
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert "target" in str(e.value)
