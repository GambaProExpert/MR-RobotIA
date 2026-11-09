# MRRobotIA — auditor de postura defensiva de LLM auto alojados

Herramienta de **auditoría defensiva** (hardening) para servidores LLM auto alojados. Primero
**identifica** con qué se está tratando (servidor, versión, cómo se arrancó y en qué sistema),
adapta las comprobaciones a lo que ha encontrado y **normaliza todo en un informe único** con
severidades y referencias a OWASP LLM Top 10 2025, MITRE ATLAS y NIST AI 600-1. Cuando es útil,
**orquesta herramientas ya consolidadas** (Julius, ssh-audit, Trivy; más adelante garak,
promptfoo y DeepEval) de forma local y offline: «la auditoría no la hace MRRobotIA; los datos
sí los saca». La hoja de ruta está en [HITOS.md](HITOS.md).

## Qué está validado y qué no

| Parte | Estado |
|---|---|
| **llama.cpp** (perfil completo: identificación, exposición, arranque y avisos de seguridad) | Probado contra un `llama-server` real (build b11583) |
| **vLLM** (mismo perfil) | Implementado a partir del código de la versión 0.33.0 y **sin validar contra un servidor real**: las pruebas usan un servidor falso que sigue esa lectura |
| Cualquier otro servicio (Ollama, LM Studio...) | Solo se reconoce (con las sondas de Julius, si está instalada) y recibe las comprobaciones comunes; no tiene perfil propio |
| Trivy y `ssh-audit` | Solo con salidas simuladas: no se han ejecutado las herramientas reales |
| Julius | Se probó a mano contra un servidor real. Dentro de MRRobotIA, que solo la invoca para lo que los perfiles no reconocen, se ha ejecutado contra un servicio que no era un LLM; el reconocimiento positivo está probado con salidas simuladas |
| Sistemas operativos | Windows 11 y Ubuntu 24.04 (WSL2); en Linux, sin `sshd` ni servidor reales |
| Pruebas automáticas | `pytest`, herméticas (servidor falso, tabla de puertos y procesos simulados) |

## Instalación
Requiere Python >= 3.10. Desde la raíz del proyecto (donde está `pyproject.toml`):
```
pip install -e .
```
Esto instala el paquete `mrrobotia` y el comando de consola `mrrobotia`. Para ejecutar las
pruebas, instala además las dependencias de desarrollo y lanza `pytest`:
```
pip install -e ".[dev]"
pytest
```
El paquete solo usa la biblioteca estándar: no añade dependencias en tiempo de ejecución.
Las herramientas externas (Julius, ssh-audit, Trivy) son opcionales y se instalan aparte; si
falta una, el informe lo dice y explica cómo instalarla.

## Uso
Copia `ejemplos/objetivo.ejemplo.json` a `objetivo.json`, ajusta las rutas y la autorización (`tengo_autorizacion` viene a `false`: ponlo a `true` solo si tienes permiso) y
ejecuta:
```
mrrobotia --objetivo objetivo.json --salida informe_mrrobotia
```
También puede ejecutarse como módulo, sin instalar (desde la raíz del proyecto, con `src` en el
`PYTHONPATH`):
```
python -m mrrobotia --objetivo objetivo.json
```
`objetivo.json` y los informes contienen rutas de tu sistema: no los subas a la nube (ya están
en `.gitignore`). Las **rutas relativas** del objetivo se resuelven contra el directorio de
trabajo desde el que lanzas el comando, no contra el fichero de objetivo.

### Opciones del comando
| Opción | Qué hace |
|---|---|
| `--objetivo` | Fichero JSON de alcance y autorización (o la variable `MRROBOTIA_OBJETIVO`) |
| `--permitir-activos` | Habilita el sondeo por red; hace falta además `permitir_activos: true` en el objetivo (o `MRROBOTIA_PERMITIR_ACTIVOS=1`) |
| `--salida` | Prefijo de los ficheros `.md` y `.json` del informe (por defecto `informe_mrrobotia`). Si su carpeta no existe, se crea; si no se puede crear o escribir, falla **antes** de escanear |
| `--escaneo` | Qué escaneos correr, por etiqueta o grupo, separados por comas. Por defecto, todos |
| `--excluir` | Etiquetas o grupos que quitar de la selección. La identificación no se puede excluir |
| `--listar` | Muestra los escaneos y los grupos (qué hace cada uno, si es pasivo o híbrido, qué herramienta externa usa y si está instalada) y termina; no necesita `--objetivo` |
| `--servidor {auto,llama.cpp,vllm}` | Fuerza el tipo de servidor en lugar de detectarlo. Si lo detectado difiere, el informe avisa del conflicto y se usa lo forzado |
| `--solo-declarado` | Audita solo el servidor del `endpoint` o del puerto declarado: no se prueban otros candidatos ni se auditan los demás servidores del host. Falla si el objetivo no declara ninguno |

Ejemplos:
```
mrrobotia --listar
mrrobotia --objetivo objetivo.json --escaneo servidor --excluir cve
mrrobotia --objetivo objetivo.json --escaneo pasivo --salida informes/hoy
mrrobotia --objetivo objetivo.json --permitir-activos --solo-declarado
mrrobotia --objetivo objetivo.json --servidor vllm
```

### Escaneos y grupos
La lista que sigue sale de `mrrobotia --listar`, que siempre está al día con el registro de
módulos.

| Etiqueta | Módulo | Qué hace | Tipo | Herramienta externa |
|---|---|---|---|---|
| `identificacion` | H2-ID | Servidor LLM, versión, cómo se arrancó y sistema. **Corre siempre y primero** | Híbrido | Julius (opcional) |
| `integridad` | M2 | SHA-256 de los artefactos (`.gguf`, bases vectoriales) frente a un hash o un manifiesto | Pasivo | — |
| `config` | M3 | Credenciales, registro de auditoría y enlace/TLS de la aplicación (`usuarios.json`, `auditoria.jsonl`) | Pasivo | — |
| `exposicion` | H2 | Enlace, propietario del proceso y sondeo HTTP de cada servidor (autenticación, CORS, TLS...) | Híbrido | — |
| `arranque` | H2-ARRANQUE | Opciones de arranque y entorno del proceso del servidor | Pasivo | — |
| `cve` | H2-CVE | Versión del servidor frente a los avisos de seguridad incluidos | Pasivo | — |
| `ssh` | H3-SSH | `sshd_config` (pasivo) y `ssh-audit` contra el servicio (activo) | Híbrido | ssh-audit |
| `puertos` | H3-PUERTOS | Puertos inesperados o peligrosos del host; barrido de conexión simple (activo) | Híbrido | — |
| `vulns` | H3-HOST | Vulnerabilidades, malas configuraciones y secretos del disco local | Pasivo | Trivy |

| Grupo | Contenido |
|---|---|
| `todo` | Todos los escaneos (por defecto) |
| `servidor` | `exposicion`, `arranque`, `cve` |
| `host` | `ssh`, `puertos`, `vulns` (la seguridad del host) |
| `activo` | `exposicion`, `ssh`, `puertos` (los que tienen parte activa; **no** la habilitan) |
| `pasivo` | Como `todo`, pero fuerza a omitir toda comprobación activa |

Un escaneo **pasivo** solo observa (disco, procesos, tabla de puertos). Uno **híbrido** hace
siempre su parte pasiva y solo con el sondeo activo autorizado hace la parte que habla con el
servicio, y entonces solo con GET, HEAD y OPTIONS (más una POST sin efecto en llama.cpp).

**El análisis del host solo se hace en máquinas con servidor LLM.** `ssh`, `puertos` y `vulns`
se omiten si el contexto no contiene un servidor llama.cpp o vLLM (identificado, declarado con la
clave `servidor` o forzado con `--servidor`). El informe deja una nota que dice por qué y cómo
forzarlo. El informe indica también qué escaneos se pidieron y cuáles se omitieron, con el motivo.
Si un módulo falla, la auditoría sigue: queda un hallazgo INFO `<módulo>-ERROR` (con solo el tipo
de la excepción) y los demás módulos corren.

### Claves del fichero de objetivo
Además de `nombre`, `autorizacion` (obligatoria), `host` y `permitir_activos`:

| Claves | Las lee | Para qué |
|---|---|---|
| `endpoint` | H2-ID y los demás | URL del servidor (p. ej. `http://127.0.0.1:8080/v1/chat/completions`); de ella salen host, puerto, esquema y prefijo |
| `servidor` | H2-ID | `"llama.cpp"`, `"vllm"` u otro nombre: el tipo declarado. Se contrasta con lo detectado (si difieren, hallazgo `H2-ID-CONFLICTO`) |
| `exposicion` | H2-ID, H2 | `puerto`, `bind_esperado`, `proxy_autenticador`, `api_key_esperada`: lo que se espera del servidor declarado |
| `manifiesto`, `manifiesto_firmado`, `artefactos` | M2 | Manifiesto de hashes y lista de `{ruta, sha256?}`. Un `sha256` que no sean 64 caracteres hexadecimales no se compara: hallazgo INFO |
| `usuarios`, `auditoria` o `dir_logs`, `app_dir` | M3 | Ficheros de la aplicación que rodea al modelo (solo lectura) |
| `ssh` | H3-SSH | `puerto` y `sshd_config` |
| `puertos` | H3-PUERTOS | `esperados` (puertos legítimos adicionales) y `extra_peligrosos` |
| `host_trivy` | H3-HOST | `ruta` (directorio a escanear), `escaneres`, `severidad` |
| `herramientas` | H2-ID, H3 | Rutas y tiempos límite por herramienta, p. ej. `{"trivy": {"ruta": "...", "timeout": 900, "cache_dir": "..."}}`. Sin esto se buscan en el `PATH` |

Las variables de entorno `MRROBOTIA_OBJETIVO` y `MRROBOTIA_PERMITIR_ACTIVOS` son alternativas a
`--objetivo` y `--permitir-activos`.

## Principios
- **Autorización explícita.** El objetivo declara que tienes permiso. Sin
  `autorizacion.tengo_autorizacion = true`, la herramienta no corre. Un host no local exige
  confirmación aparte (`confirmo_no_local`). Es el equivalente al consentimiento de un pentest.
- **Lectura por defecto.** Los escaneos pasivos solo observan. El sondeo por red exige
  `--permitir-activos` y `permitir_activos: true` en el objetivo.
- **Solo tu infraestructura o con permiso escrito.** No escanea ni prueba sistemas de terceros.
- **Nada sensible en el informe.** Las líneas de órdenes se reducen a una lista blanca de
  opciones; las claves, los tokens y las rutas absolutas de modelos no se guardan, solo su presencia.
- **Orquestar, no reinventar.** Las herramientas externas se ejecutan con `subprocess`, con la
  orden como lista y sin `shell=True`; si no están instaladas, se informa y no se da la
  comprobación por hecha.

## Modelo de amenazas
La herramienta se pensó para auditar despliegues frente a estos cinco atacantes:

| ID | Atacante | Qué cubre hoy MRRobotIA |
|---|---|---|
| A1 | Usuario legítimo de otro rol: escribe cualquier texto (jailbreak, inyección) | Nada todavía (H4 y H5, pendientes) |
| A2 | Documento envenenado: controla el contenido que entra al sistema | Nada todavía (H5, pendiente) |
| A3 | Interno con acceso a disco o a otros procesos del host | Permisos y configuración (M3), procesos y entorno (H2-ARRANQUE), puertos locales (H3) |
| A4 | Cadena de suministro: modelo, adaptador o librería manipulados | Integridad de artefactos (M2), avisos de seguridad (H2-CVE), Trivy (H3-HOST) |
| A5 | Exposición del servicio en red | Enlace, autenticación, CORS, TLS y puertos (H2, H3) |

## Estructura del proyecto
```
MRRobotIA/
├── pyproject.toml          # empaquetado (src-layout, comando `mrrobotia`)
├── README.md
├── CHANGELOG.md
├── HITOS.md                # hoja de ruta por capas (hitos)
├── Guia_agentes.md         # enfoque de orquestación (origen del rediseño)
├── LICENSE
├── ejemplos/
│   └── objetivo.ejemplo.json
├── src/mrrobotia/
│   ├── __init__.py         # __version__
│   ├── __main__.py         # `python -m mrrobotia`
│   ├── cli.py              # comando: selector de escaneos, ejecución y salida
│   ├── nucleo.py           # hallazgos, autorización, informe y clase base de módulo
│   ├── contexto.py         # qué se ha identificado (servidores, versión, enlace...)
│   ├── herramientas.py     # núcleo orquestador de herramientas externas
│   ├── red.py              # utilidades de red/SO (puertos, enlace, sondeo, cliente HTTP)
│   ├── procesos.py         # lectura de procesos locales (línea de órdenes, entorno)
│   ├── cve.py              # comparación de versiones con los avisos de seguridad
│   ├── perfiles/           # un perfil por servidor: llamacpp.py, vllm.py y genérico
│   ├── datos/
│   │   ├── cve_llamacpp.json   # avisos de seguridad de llama.cpp
│   │   ├── cve_vllm.json       # avisos de seguridad de vLLM
│   │   └── julius_sondas/      # sondas de Julius (licencia propia incluida)
│   └── modulos/
│       ├── h2_identificacion.py # H2-ID: identifica el servidor
│       ├── h2_exposicion.py     # H2: inventario y exposición por servidor
│       ├── h2_arranque.py       # H2-ARRANQUE: opciones y entorno de arranque
│       ├── h2_cve.py            # H2-CVE: versión frente a avisos
│       ├── m2_integridad.py     # M2: SHA-256 de artefactos
│       ├── m3_configuracion.py  # M3: configuración de la aplicación
│       ├── h3_ssh.py            # H3: endurecimiento de SSH
│       ├── h3_puertos.py        # H3: puertos del host
│       └── h3_host.py           # H3: Trivy
└── tests/                  # pytest; servidor_falso.py simula llama.cpp y vLLM
```

## Hitos (resumen)
El detalle, el orden y qué extrae cada hito están en [HITOS.md](HITOS.md).

| Hito | Capa | Estado |
|---|---|---|
| H0 Núcleo orquestador | — | Hecho |
| H1 Integridad de artefactos (SHA-256) | 1 | Hecho |
| H2 Identificación, exposición, arranque y avisos | 1 | Hecho; llama.cpp validado con un servidor real, **vLLM pendiente de validar** |
| H3 Seguridad del host (SSH, puertos, Trivy) | 1 | Hecho; Trivy y ssh-audit solo con salidas simuladas |
| H4 Barrido del endpoint | 2 | Pendiente (garak) |
| H5 Prompt injection y evals | 2 | Pendiente (promptfoo) |
| H6 Prompts y salidas no salen de la red | 2 | Pendiente (DeepEval) |

## No incluye
- Extracción de secretos de la memoria de procesos.
- Generación de carga para agotar recursos (DoS).
- Escaneo o prueba de sistemas ajenos.
