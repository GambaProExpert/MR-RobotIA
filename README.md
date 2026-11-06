# MRRobot — auditor de postura defensiva de LLM auto alojados

Suite de **auditoría defensiva** (hardening) para despliegues locales de modelos
abiertos, parte del TFG. Revisa la postura de seguridad de **infraestructura propia**
y produce un informe con severidades y referencias a OWASP LLM Top 10 2025, MITRE
ATLAS y NIST AI 600-1. Es el complemento operativo de `../MODELO_AMENAZAS.md`: cada
módulo cubre uno de los atacantes A1–A5.

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

## Principios (y por qué son parte del TFG)
- **Autorización explícita.** El objetivo (`objetivo.json`) declara que tienes permiso.
  Sin `autorizacion.tengo_autorizacion = true`, la herramienta no corre. Un host no
  local exige confirmación aparte. Es el equivalente al consentimiento de un pentest.
- **Lectura por defecto.** Los módulos pasivos solo observan. Un módulo *activo*
  (que interactúa con el servicio) se omite salvo `--permitir-activos` y
  `permitir_activos=true` en el objetivo.
- **Solo tu infraestructura o con permiso escrito.** No escanea ni prueba sistemas
  de terceros.

## Estructura del proyecto
```
MRRobot/
├── pyproject.toml          # empaquetado (src-layout, comando `mrrobot`)
├── README.md
├── CHANGELOG.md
├── LICENSE
├── ejemplos/
│   └── objetivo.ejemplo.json
├── src/
│   └── mrrobot/
│       ├── __init__.py     # __version__
│       ├── __main__.py     # `python -m mrrobot`
│       ├── cli.py          # punto de entrada del comando `mrrobot`
│       ├── nucleo.py       # hallazgos, autorización e informe
│       └── modulos/
│           ├── __init__.py
│           ├── m2_integridad.py
│           └── m3_configuracion.py
└── tests/
    ├── test_nucleo.py
    ├── test_m2.py
    └── test_m3.py
```

## Módulos (hoja de ruta)
| Módulo | Atacante | Estado | Qué comprueba |
|---|---|---|---|
| M2 Integridad de artefactos | A4, A3 | **Hecho** | SHA-256 de `.gguf` y `chroma.sqlite3` contra un manifiesto firmado; ausentes, alterados, sin firma |
| M1 Robustez de prompts | A1 | Pendiente (defensivo) | Pasa la batería de jailbreak/inyección y mide fuga neta y rechazo (reutiliza `Caso1/v2/evaluar.py`) |
| M3 Auditoría de configuración | A3, A5 | **Hecho** | PBKDF2 (iteraciones/sal/hash) y contraseñas en claro en `usuarios.json`; que la auditoría guarde solo el hash de la pregunta, no su texto; rotación y permisos de los logs; enlace de red y TLS (`.streamlit/config.toml`). Mapea a OWASP LLM02 y NIST AI 600-1 (2.4, 2.9) |
| M4 Higiene de secretos | A3 | Pendiente (defensivo) | Configuración que expone secretos: permisos de fichero, swap/volcados, secretos en entorno o logs |
| M5 Resiliencia y límites | A5 | Pendiente (defensivo) | Revisión de límites (consultas, timeout, contexto, concurrencia) y prueba de carga controlada contra tu propio servicio |

M4 y M5 son **defensivos por diseño**: M4 no extrae memoria de procesos, comprueba
que la configuración no exponga secretos; M5 no es una herramienta de DoS, mide el
punto de saturación de tu propio servicio para recomendar límites y se detiene al
degradar.

## No incluye
- Extracción de secretos de la memoria de procesos.
- Generación de carga para agotar recursos (DoS).
- Escaneo o prueba de sistemas ajenos.
