# MRRobot — auditor de postura defensiva de LLM auto alojados

Herramienta de **auditoría defensiva** (hardening) para **cualquier servidor LLM auto
alojado** (llama.cpp, Ollama, vLLM, LM Studio…). MRRobot **orquesta herramientas ya
consolidadas** (garak, promptfoo, Trivy, DeepEval…) de forma local y offline y
**normaliza sus datos** a un informe único con severidades y referencias a OWASP LLM
Top 10 2025, MITRE ATLAS y NIST AI 600-1: «la auditoría no la hace MRRobot; los datos
sí los saca». El laboratorio del TFG es solo uno de los objetivos posibles. La hoja de
ruta por capas está en [HITOS.md](HITOS.md); el modelo de amenazas (atacantes A1–A5),
en `../MODELO_AMENAZAS.md`.

## Instalación
Requiere Python >= 3.10. Desde la raíz del proyecto (donde está `pyproject.toml`):
```
pip install -e .
```
Esto instala el paquete `mrrobot` y el comando de consola `mrrobot`. Para ejecutar
las pruebas, instala además las dependencias de desarrollo:
```
pip install -e ".[dev]"
```
El paquete solo usa la biblioteca estándar: no añade dependencias en tiempo de
ejecución.

## Uso
```
mrrobot --objetivo ejemplos/objetivo.ejemplo.json --salida informe_mrrobot
```
También puede ejecutarse como módulo, sin instalar:
```
python -m mrrobot --objetivo ejemplos/objetivo.ejemplo.json
```
Copia `ejemplos/objetivo.ejemplo.json` a `objetivo.json`, ajusta rutas y
autorización, y ejecútalo. `objetivo.json` y los informes contienen rutas de tu
sistema: no los subas a la nube (ya están en `.gitignore`).

### Claves del fichero de objetivo
Además de `autorizacion`, `host` y `permitir_activos`, cada módulo lee sus propias claves
(todas son rutas que M3 solo **lee**; una ruta que no exista genera un hallazgo INFO):
- **M2:** `manifiesto`, `manifiesto_firmado`, `artefactos` (lista de `{ruta, sha256?}`).
- **M3 (configuración):**
  - `usuarios` — ruta de `usuarios.json` (PBKDF2, contraseñas en claro, permisos).
  - `auditoria` — ruta del `auditoria.jsonl`, **o** `dir_logs` (directorio donde buscar `auditoria.jsonl`).
  - `app_dir` *(opcional)* — directorio de la app; M3 busca en él `.streamlit/config.toml` para revisar `server.address` y TLS.
- **H2 (exposición):** `endpoint` — URL base del servidor LLM (p. ej. `http://127.0.0.1:8080`);
  `exposicion` *(opcional)* con `puerto`, `bind_esperado`, `proxy_autenticador`, `api_key_esperada`
  y `builds_vulnerables`. La parte activa (sondeo del endpoint) solo corre con `--permitir-activos`.
- **Núcleo orquestador (H0+):** `herramientas` *(opcional)* — overrides por herramienta, p. ej.
  `{"garak": {"ruta": "/ruta/a/garak", "timeout": 1200}}`. Sin esto, cada herramienta se busca
  en el `PATH` y se usa un timeout por defecto.

## Principios (y por qué son parte del TFG)
- **Autorización explícita.** El objetivo (`objetivo.json`) declara que tienes permiso.
  Sin `autorizacion.tengo_autorizacion = true`, la herramienta no corre. Un host no
  local exige confirmación aparte. Es el equivalente al consentimiento de un pentest.
- **Lectura por defecto.** Los módulos pasivos solo observan. Un módulo *activo*
  (que interactúa con el servicio) se omite salvo `--permitir-activos` y
  `permitir_activos=true` en el objetivo.
- **Solo tu infraestructura o con permiso escrito.** No escanea ni prueba sistemas
  de terceros.

## Modelo de orquestación
MRRobot no reimplementa cada comprobación: **ejecuta herramientas externas** a través de
`ModuloHerramienta` (`mrrobot.herramientas`) y normaliza su salida al informe. El patrón:
1. **Detecta** la herramienta (`PATH` o la ruta declarada en `objetivo['herramientas']`); si no
   está, emite un hallazgo **INFO** con cómo instalarla y no sigue — nunca la da por ejecutada.
2. La **ejecuta** por `subprocess`, siempre con la orden como lista y **nunca `shell=True`**,
   con timeout y captura de salida, de forma local y offline.
3. **Normaliza** su salida (JSON/JSONL/texto) a `Hallazgo` con severidad y marcos.
4. Deja un hallazgo de **trazabilidad** con la versión usada, para resultados reproducibles.

Así, cada hito de herramienta (H3 Trivy, H4 garak, H5 promptfoo, H6 DeepEval) solo aporta su
envoltorio. MRRobot no añade dependencias de ejecución: las herramientas externas son
prerrequisitos del sistema que se instalan aparte.

## Estructura del proyecto
```
MRRobot/
├── pyproject.toml          # empaquetado (src-layout, comando `mrrobot`)
├── README.md
├── CHANGELOG.md
├── HITOS.md                # hoja de ruta por capas (hitos)
├── Guia_agentes.md         # enfoque de orquestación (origen del rediseño)
├── LICENSE
├── ejemplos/
│   └── objetivo.ejemplo.json
├── src/
│   └── mrrobot/
│       ├── __init__.py     # __version__
│       ├── __main__.py     # `python -m mrrobot`
│       ├── cli.py          # punto de entrada del comando `mrrobot`
│       ├── nucleo.py       # hallazgos, autorización e informe
│       ├── herramientas.py # núcleo orquestador (H0): ejecuta herramientas externas
│       ├── datos/          # recursos (p. ej. probes_base.jsonl)
│       └── modulos/
│           ├── __init__.py
│           ├── m2_integridad.py
│           ├── m3_configuracion.py
│           ├── h2_exposicion.py     # H2: inventario y exposición del servidor LLM
│           └── m1_robustez.py       # prober propio previo (sin cablear); a sustituir por garak en H4
└── tests/
    ├── test_nucleo.py
    ├── test_m2.py
    ├── test_m3.py
    ├── test_herramientas.py
    └── test_h2.py
```

## Hitos (resumen)
Cada herramienta externa es un hito; el detalle, el orden y qué extrae cada uno están
en [HITOS.md](HITOS.md). MRRobot **orquesta y normaliza**, no reimplementa.

| Hito | Capa | Base | Atacante | Estado |
|---|---|---|---|---|
| H0 Núcleo orquestador | — | propio | — | **Hecho** |
| H1 Integridad de artefactos (SHA-256) | 1 | propio (M2) | A4, A3 | **Hecho** |
| M3 Configuración (se integra en H2) | 1 | propio | A3, A5 | **Hecho** |
| H2 Inventario y exposición (bind, puertos, usuario, claves) | 1 | propio | A5, A3 | **Hecho** |
| H3 Vulnerabilidades del host | 1 | Trivy | A4, A3 | Pendiente |
| H4 Barrido del endpoint | 2 | garak | A1 | Pendiente |
| H5 Prompt injection / evals | 2 | promptfoo | A1 | Pendiente |
| H6 Prompts/salidas no salen de la red | 2 | DeepEval | A1, A5 | Pendiente |

El prober propio `modulos/m1_robustez.py` quedó de una iteración previa; su función
(barrido del endpoint) la asume **garak** en H4, donde se reconcilia.

## No incluye
- Extracción de secretos de la memoria de procesos.
- Generación de carga para agotar recursos (DoS).
- Escaneo o prueba de sistemas ajenos.
