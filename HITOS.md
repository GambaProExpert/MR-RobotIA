# MRRobotIA — Hitos (roadmap por capas)

> Operativiza [Guia_agentes.md](Guia_agentes.md). Alcance elegido: **LLM + RAG + host**.
> Estado de este documento: versión 0.14.0 (2026-11-22). H0-H6 hechos; H7 por hacer (con el diseño hecho). vLLM está validado contra un
> vLLM 0.33.0 real en CPU; quedan por validar GPU, generación y el escaneo real de ssh-audit (ver más abajo). Trivy ya está validado en real (0.11.0).

## Qué es ahora MRRobotIA

Un **orquestador defensivo**: no reimplementa cada comprobación, sino que **ejecuta herramientas
ya consolidadas** contra un servidor LLM local y **normaliza sus datos** a un informe único
(`Hallazgo` + `Severidad` + marcos OWASP LLM Top 10 2025 · MITRE ATLAS · NIST AI 600-1).
«La auditoría no la hace MRRobotIA; los datos sí los saca.» Cada herramienta = un hito.

### Principios

- **Orquestar, no reinventar.** Si una herramienta no está instalada, MRRobotIA emite un hallazgo
  informativo con cómo instalarla; nunca revienta ni la da por ejecutada.
- **Todo local y offline.** Nada de prompts ni salidas sale de la red (ver H6, *muy importante*).
- **Deny-by-default + doble consentimiento** para módulos activos (ya en el núcleo).
- **Sin dependencias de ejecución nuevas en MRRobotIA**: las herramientas externas se invocan por
  `subprocess` y su salida (JSON/JSONL) se parsea a `Hallazgo`.

## Hitos

| Hito | Capa | Base / herramienta | Qué extrae | Estado |
|---|---|---|---|---|
| **H0 · Núcleo orquestador** | — | código propio | `Herramienta`/`ModuloHerramienta`: detectar (`which`/versión), ejecutar con *timeout* y sin `shell=True`, parsear salida a `Hallazgo`, mapear marcos; rutas de herramientas por objetivo | **hecho** |
| **H1 · Integridad SHA-256** | 1 | código propio (M2) | hashes de modelos/adaptadores/índices frente a manifiesto o `sha256` en línea; un `sha256` mal formado no cuenta como alteración | **hecho** |
| **H2 · Identificación, exposición, arranque y avisos** | 1 | código propio (+ Julius opcional) | **H2-ID** identifica antes de auditar el servidor (llama.cpp o vLLM), versión, arranque y SO; **H2** evalúa por servidor *bind* (loopback vs `0.0.0.0`), autenticación, CORS, `Host`, TLS y los endpoints propios del perfil; **H2-ARRANQUE** revisa opciones y entorno; **H2-CVE** compara la versión con 48 avisos de llama.cpp y 140 de vLLM. Puertos por defecto de llama.cpp: **9931** (builds recientes) y **8080**; de vLLM, 8000 | **hecho** · llama.cpp validado contra un servidor real; **vLLM implementado desde el código de la 0.33.0 y validado contra un vLLM 0.33.0 real en CPU (peticiones de lectura)** |
| **H3 · Seguridad del host** | 1 | código propio + **Trivy** + ssh-audit | SSH (`sshd_config` CIS + `ssh-audit`), puertos abiertos innecesarios/inseguros (los puertos esperados salen de lo identificado) y vulnerabilidades/secretos/config con Trivy. Solo se ejecuta en máquinas con un servidor llama.cpp o vLLM. | **hecho** · Trivy validado en real (0.11.0); ssh-audit instalado y detectado, escaneo real pendiente (sin sshd) |
| **H4 · Barrido del endpoint** | 2 | **garak** (NVIDIA) | barrido amplio del endpoint REST/llama.cpp (sondas de inyección y más) → informe JSONL normalizado | **hecho** (0.10.0) · **sustituye al *prober* propio anterior** (fuera del repositorio). Validado contra un llama.cpp real (7B) con configuración automática, `garak-config.json` REST pegado y tiempo agotado con informe parcial; **vLLM sin validar en real** (solo pruebas herméticas). Duración medida solo para `quick` (unos 4-6 min); `standard` y `full` son estimaciones |
| **H5 · Prompt injection / evals** | 2 | **promptfoo** | red team + evals en YAML como *gate* de CI: inyección directa e indirecta, fuga entre sesiones, agencia excesiva, BOLA/BFLA | **hecho** (0.13.0) · validado contra un llama.cpp real con Qwen2.5-7B (`gate`, `quick`, configuración de promptfoo pegada y servidor caído) y con la red bloqueada. Salvedades: **un juez del mismo modelo es poco fiable** (aprobó un volcado del system prompt; la señal de confianza son los canarios), los plugins generados necesitan un atacante mayor (un 7B escribe ataques flojos) y 18 plugins solo remotos (BOLA, BFLA, inyección indirecta...) se sustituyen por pruebas fijas y `custom_tests`. `standard`, `full`, vLLM y un juez mayor sin validar |
| **H6 · Datos no salen de la red** | 2 | código propio (biblioteca estándar: tablas de sockets por PID) | **MUY IMPORTANTE**: canales de salida configurados (telemetría, descargas, RPC, MCP, trazas, eventos KV) y conexiones salientes del árbol de procesos del servidor, en reposo y con tráfico de canario. DeepEval/DeepTeam **no forman parte de H6**: se integrarán aparte, como segundo motor de H5 | **hecho** (0.14.0) · validado contra un llama.cpp real (0 salidas) y un vLLM 0.33.0 real en CPU en WSL; positivo controlado con un servidor falso. Límites: TLS (destino, no contenido), muestreo, solo el árbol del servidor, WSL solo desde dentro |
| **H7 · Simulación de ataques con verificación** | 2 | código propio + **Schemathesis** y **vegeta** opcionales | ataques inocuos y acotados contra el servidor (o la pasarela o aplicación de delante) y, por cada uno: ¿se bloqueó?, ¿quedó constancia (logs, métricas, auditoría)?, ¿se recuperó el servidor? Remedio y repetición de lo que falló | por hacer (diseño hecho; ver abajo) |
| Capa 3 · agentes, MCP, herramientas | 3 | agentic-radar, etc. | superficie de agentes/MCP | **más adelante** (fuera de alcance ahora) |

### Alias de los hitos

Cada hito tiene un alias inspirado en las personalidades (*alters*) de la serie *Mr. Robot*, que da
nombre a la herramienta. Es solo una forma de recordar el papel de cada hito; los identificadores
del código y del informe siguen siendo `H0`…`H7`.

| Hito | Alias | Personaje | Por qué |
|---|---|---|---|
| H0 · Núcleo orquestador | `Mastermind` | El Cerebro (el Vigilante) | Toma el control operativo: dirige las herramientas, organiza las rutas y ejecuta las órdenes sin comprometer el sistema (nunca con `shell=True`). Es el arquitecto que mueve los hilos |
| H1 · Integridad SHA-256 | `Real_Elliot` (o `Host`) | El verdadero Elliot | La verdad original e inalterable: comprueba que modelos, adaptadores e índices siguen siendo exactamente lo que eran, sin manipular |
| H2 · Identificación, exposición, arranque y avisos | `The_Voyeur` (o `Hello_Friend`) | El espectador | El observador silencioso: antes de actuar mira desde fuera qué servidor corre, sus puertos y su configuración (`0.0.0.0`, TLS, CORS) y la compara con los avisos conocidos (CVE) |
| H3 · Seguridad del host | `Magda` (o `Persecutor`) | La madre | La figura estricta y severa: audita la máquina con mano dura (CIS, ssh-audit, Trivy) buscando malas configuraciones, secretos expuestos o puertas mal cerradas |
| H4 · Barrido del endpoint | `fsociety` (o `Darlene`, `Fuzz_Mask`) | La máscara, el colectivo | El ataque masivo, ruidoso y sistemático: con garak lanza muchas sondas de inyección para probar la resistencia del endpoint desde distintos ángulos |
| H5 · Prompt injection y evals | `White_Rose` (o `Dark_Army`) | Whiterose (la manipulación) | La mente maestra de la manipulación: inyección directa e indirecta, fuga entre sesiones y abuso de privilegios (BOLA/BFLA) como *gate* de CI |
| H6 · Datos no salen de la red | `Young_Elliot` (o `Safe_Room`) | El Elliot niño | La necesidad absoluta de aislamiento: que prompts y salidas nunca salgan del entorno local (se comprueba mirando las conexiones del servidor) |
| H7 · Simulación de ataques con verificación | `Mr_Robot` | El protector | Entra en acción en los momentos críticos: lanza ataques controlados y comprueba si el sistema resiste, si deja rastro y si se recupera |

## Orden propuesto

`H0 → H2 → H3 → H4 → H5 → H6 → H7`

- **H0, H2 y H3 no dependen** de instalar garak ni promptfoo: son el cimiento y la Capa 1.
- **H4 y H5** sí requieren esas herramientas en local; **H6** es código propio. Se abordan después del núcleo.
- **H7** va después de H4-H6 (decisión del 16/11/2026), aunque su primera fase no depende de ellos:
  cuando estén, sus sondas sirven como carga útil del H7.

## H7 · Simulación de ataques con verificación de detección y recuperación (diseño, 16/11/2026)

H2-H3 miran la configuración y H4-H5 mirarán el modelo. El H7 mira **la plataforma en funcionamiento**,
con un ejercicio de *purple team*: lanza ataques **inocuos y acotados** y responde tres preguntas por
ataque: **¿se bloqueó?**, **¿quedó constancia?** y **¿se recuperó?**

- **Enfoque híbrido.** Un catálogo mínimo y seguro, propio y declarativo, más adaptadores opcionales a
  Schemathesis (*fuzzing* sobre OpenAPI) y vegeta (carga a ritmo fijo), invocados por `subprocess`; si
  faltan, hallazgo informativo, como con Trivy. Lo propio es la verificación: vigilancia de vida,
  correlación de evidencias y repetición.
- **Ciclo de cada escenario**, ejecutados de uno en uno:
  1. línea base (`/health` y generación mínima);
  2. ataque marcado;
  3. vigilancia de vida (salud, latencia, PID o reinicio);
  4. búsqueda de evidencias;
  5. veredicto con remedio;
  6. entrada en el fichero de repetición.
- **Veredicto:**
  - bloqueado y detectado: INFO;
  - bloqueado sin constancia: MEDIA (sin trazabilidad);
  - no bloqueado: ALTA;
  - el servidor no se recupera en el tiempo fijado o cambia de proceso: CRÍTICA.
- **Dos marcas por ejecución.** Un `run_id` en `User-Agent` y `X-Request-Id` (si aparece en un log, el
  intento quedó registrado) y un **canario** distinto dentro del prompt (si aparece en un log o en otra
  respuesta, el sistema guarda o expone prompts en claro).
- **Evidencias**, todas de solo lectura:
  - log de peticiones del servidor o de la pasarela;
  - diferencia de métricas entre antes y después;
  - `journalctl` y `docker logs`;
  - registro de auditoría JSONL, cuya cadena de hashes se verifica tras el ataque.
  
  Correlación en cascada: marca exacta, diferencia de métricas y, como último recurso, ventana temporal
  con tipo de evento.
- **Salvaguardas («atacar sin hacer daño»):**
  - doble consentimiento (`-a` más autorización en el objetivo) y etiqueta `redteam` **fuera de `all`**;
  - presupuesto de peticiones, concurrencia, `max_tokens` (1-8) y tiempos;
  - cortafuegos que aborta si el servidor se degrada;
  - rutas con efectos siempre prohibidas, según el perfil de cada servidor;
  - en llama.cpp, lecturas con efecto (`/metrics` pone contadores a cero; `/slots` despierta un servidor
    dormido) solo con precaución;
  - niveles de riesgo `seguro`, `carga` y `arriesgado` (este último con `allow_risky`);
  - nunca reproducir un CVE que H2-CVE ya infiere por la versión;
  - una generación mínima de prueba antes de nada.
- **Familias de escenarios:**
  - autenticación (sin clave, clave errónea, variantes de cabecera);
  - consumo (tope de tokens, contexto excedido, parámetros caros, ráfaga acotada, desconexión a mitad
    del *stream*);
  - entradas malformadas y marcadores de plantilla (comprobados con `/tokenize`, sin generar);
  - fuga entre sesiones y de prompts a los logs;
  - uso de adaptadores por petición sin RBAC delante (llama.cpp);
  - SSRF con un escuchador propio en loopback (vLLM multimodal);
  - gramáticas patológicas (arriesgado).
- **Objetivo:** claves nuevas `evidence` (logs, unidad de journal, contenedor, métricas, auditoría) y
  `redteam` (límites y tiempos).
- **Comando:** `-s redteam` y `--retest <informe.json>`. Este último repite solo lo que falló y lo marca
  como `corregido`, `sigue` o `empeora`.
- **Entregas:**
  - H7a: ciclo, vigilancia, evidencias, autenticación, entradas y fugas;
  - H7b: consumo y carga;
  - H7c: repetición y reglas de detección sugeridas;
  - H7d: adaptadores y objetivos de tipo pasarela o aplicación;
  - H7e: canario periódico.
- **Validación prevista:**
  - llama.cpp real en local;
  - vLLM real (con compilador de C para los escenarios que generan);
  - una API con autenticación, límites y auditoría encadenada.
- **Publicación del catálogo** (decidido el 16/11/2026): se publica, pero en el repositorio solo entran
  escenarios de fallos **ya divulgados y corregidos**, citando su aviso (CVE/GHSA). Un fallo nuevo que
  encuentre el H7 se comunica antes en privado al proyecto afectado y no entra hasta que se publique.

## Qué declara cada hito (a rellenar con savvy-flow)

Para cada hito, la investigación debe fijar: instalación **local y offline**; comando exacto
contra un endpoint **llama.cpp**; formato de salida y su parseo; mapeo a severidad + marcos
(OWASP·ATLAS·NIST); si es módulo **activo** o pasivo; y pruebas sin red ni modelo.

## Estado del repositorio

- Hecho: núcleo (`nucleo.py`, `herramientas.py`), identificación y perfiles, H1/M2, M3 de
  configuración (se integra en H2 para aplicaciones con login), H2 completo y H3.
- Selector del comando: `--scan`, `--skip`, `--list`, `--server` y `--declared-only` (opciones cortas e inglesas desde la 0.7.0).
- **Validado:** vLLM 0.33.0 real en CPU, solo con peticiones de lectura (GET y OPTIONS).
- **Sigue sin validar:** vLLM en GPU y con generación, y el **escaneo real de ssh-audit** (instalado y
  detectado con su versión, pero sin ningún `sshd` local contra el que probarlo; no se escanea ningún
  servidor ajeno).
- **Trivy (0.11.0):** validado en real con la 0.76.2 (instalada con la guía y la suma SHA-256 comprobada)
  en H3 `vulns` sobre carpetas reales de solo lectura, incluidos hallazgos reales; solo el modo sin red,
  con la base descargada antes (134 MB de descarga, 1,7 GB descomprimida).
- **Herramientas externas (0.11.0):** MRRobotIA no las instala; `--check-tools` y `docs/TOOLS.md` /
  `docs/HERRAMIENTAS.md` dicen cómo, desde un catálogo único (`instalacion.py`). Las órdenes de
  Windows están ejecutadas; las de Linux y macOS, sin ejecutar.
- **H4 (0.10.0):** garak sustituye por completo al *prober* propio anterior, que sigue fuera del
  repositorio y no se recupera. Etiqueta `garak`, fuera de `all`, con doble consentimiento. Validado
  contra un llama.cpp real; la configuración automática para vLLM solo tiene pruebas herméticas
  (**sin validar en real**: el vLLM de WSL no puede generar). Lo que garak no cubre (el system prompt
  propio de una aplicación, con sus canarios) lo cubre H5 (promptfoo).
- **H5 (0.13.0):** promptfoo evalúa el comportamiento del chatbot con su system prompt, propósito y límites.
  Etiqueta `promptfoo`, fuera de `all`, con doble consentimiento. Requiere **Node.js >= 22.22** (con uno
  anterior promptfoo no arranca: `H5-PROMPTFOO-NODE-ANTIGUO`) y promptfoo 0.126.0; `--check-tools` y
  `docs/TOOLS.md` / `docs/HERRAMIENTAS.md` los cubren. Decisiones:
  - **Todo local, requisito duro** (el germen de H6): en cada subproceso, incluso la consulta de versión,
    se fuerzan telemetría, comprobación de versión, compartir y generación remota desactivados, proxy
    muerto con `NO_PROXY` solo para el chatbot y el juez, y `PROMPTFOO_CONFIG_DIR` dentro de la salida.
    Medido: `PROMPTFOO_DISABLE_TELEMETRY=1` por sí sola **no** basta (promptfoo sigue enviando un evento a
    `r.promptfoo.app`); con el bloqueo, un oyente en el proxy muerto solo vio esos intentos y el muestreo
    de las conexiones de `node` no vio ningún destino externo. **Falla cerrado**: solo plugins y estrategias
    verificados como locales; lo demás sale como INFO `H5-PROMPTFOO-REMOTO-OMITIDO`.
  - **El juez es el servidor local** (por defecto el del propio chatbot). Un 7B que se juzga a sí mismo
    aprobó un volcado completo del system prompt: por eso hay **canarios** deterministas (la señal de
    confianza), **calibración del juez** antes de ejecutar, el hallazgo `H5-PROMPTFOO-JUEZ-MISMO-MODELO` y
    una frase fija en el informe («un resultado limpio con un juez del mismo modelo no demuestra
    seguridad»).
  - **Presets** `quick`, `standard`, `gate` y `full`; `gate` (solo el paquete de pruebas fijas más las
    `custom_tests`) es el de CI: determinista y de 1 a 4 min. El *gate* lo da la **severidad de los
    hallazgos**: no hay una opción global nueva en el CLI.
  - Se puede **pegar una configuración de promptfoo** (`promptfoo.config`, como objeto JSON) o apuntar a un
    fichero; MRRobotIA la revisa (claves en claro, código, juez no local, pruebas descargadas de la red).
  - Marcos: OWASP LLM 2025; ATLAS y NIST solo donde coinciden con H4 y, en autorización, solo OWASP.
  - Sin dependencias de ejecución nuevas: no se lee YAML (sin PyYAML la configuración pegada va en JSON).
  - **Sin validar / límites:** estrategias iterativas (`jailbreak`, `crescendo`...), `{{env.X}}` en
    cabeceras, `--safe-mode` con aserciones `javascript`, `::1` en `NO_PROXY`, vLLM, `standard`, `full` y un
    juez mayor que el chatbot. promptfoo solo escribe su JSON al terminar cada fase.
  - Un juez distinto del sujeto (el 14B de otro puerto, con `promptfoo.judge.url`) queda documentado y medido en H6.
- **H6 (0.14.0):** comprobación directa de si los datos salen de la red; código propio, solo biblioteca
  estándar. Etiqueta `egress`, módulo híbrido que **entra en `all` solo con la auditoría estática**; la ventana
  de observación y los canarios exigen `-a` con `allow_active` (la ventana pasiva también corre con `-s egress`).
  Decisiones:
  - **Opción B, sin DeepEval/DeepTeam en H6.** Medido: no responden a «¿salen datos de la red?» (evalúan lo que
    el modelo dice: es H4/H5), y son ellos mismos un canal de salida: unos 30 intentos de telemetría por
    ejecución (PostHog, New Relic, IP pública), subida de ataques y respuestas a su nube si hay clave, y
    DeepTeam solo se corta con el valor literal `YES`. **Se integrarán aparte, como segundo motor de H5**, con
    `DEEPEVAL_TELEMETRY_OPT_OUT=1`, `DEEPTEAM_TELEMETRY_OPT_OUT=YES` y un juez local, con la red bloqueada como
    promptfoo.
  - **Método:** muestreo de la tabla de sockets del sistema por PID (Windows `GetExtendedTcpTable` y
    `CreateToolhelp32Snapshot`; Linux `/proc/<pid>/net/*` e inodos de `/proc/<pid>/fd`) sobre el **árbol** de
    procesos del servidor, recalculado en cada muestra. Clases: escucha, entrante, pull, propia, permitida,
    DNS, UDP y SALIDA (pública o privada). **Canario** (`MRR-H6-<12 hex>`, nunca impreso) por `chat` con
    `max_tokens` 8 o por `tokenize`, y correlación de peticiones con conexiones nuevas.
  - **H6 es el único dueño de los canales de salida.** La comprobación de telemetría de vLLM salió de
    H2-ARRANQUE (`H2-ARRANQUE-TELEMETRIA`) y es `H6-SALIDAS-CANAL-TELEMETRIA`. Se corrigió un **fallo real**: vLLM
    solo acepta `DO_NOT_TRACK`, `VLLM_DO_NOT_TRACK` y `VLLM_NO_USAGE_STATS` con el valor exacto `1` (con
    `true` envía igual, medido) y MRRobotIA daba por buena cualquier valor: ahora sale
    `H6-SALIDAS-CANAL-TELEMETRIA-EXCLUSION-INVALIDA`.
  - **Severidades:** estadísticas de uso de vLLM, BAJA (no llevan prompts); eventos KV por ZMQ sin
    autenticación, ALTA (los `token_ids` son los del prompt); salida a internet, ALTA; a la red local, MEDIA;
    correlacionada con el canario, CRÍTICA (pública).
  - **Validado:** llama.cpp real (0 conexiones salientes con cientos de peticiones), vLLM 0.33.0 real en CPU
    dentro de WSL (auditoría estática con y sin `HF_HUB_OFFLINE`, `DO_NOT_TRACK=true` frente a `=1`, eventos KV
    y un intento real de llegar al hub, visto como `SYN_SENT`) y un servidor falso que intenta conectar a una
    dirección sin dueño al recibir un canario (positivo controlado; nada salió de la máquina).
  - **Límites:** con TLS se ve el destino, no el contenido; el muestreo puede perder conexiones de menos de unos
    100 ms (medido: 20 de 20 desde 100 ms, 4-8 de 20 con 20 ms, ninguna al instante); solo se ve el árbol del
    servidor y solo durante la ventana; el DNS no se atribuye al servidor; un servidor dentro de WSL no se ve desde
    Windows (hay que ejecutar MRRobotIA dentro de WSL); en Windows el entorno de otro proceso no se lee y la
    tabla UDP no da la remota. vLLM en GPU y su ruta de generación sin validar.
  - **El juez distinto del sujeto** que dejó pendiente H5 se resuelve en H5 con `promptfoo.judge.url` apuntando
    a otro modelo local mayor (H5 ya lo admitía). Medido: el 7B juzgándose a sí mismo marcó 19 de 24
    respuestas como vulnerables sin fuga alguna; el juez 14B (CPU, unos 26 s por evaluación) no marcó ninguna
    por error pero dejó pasar 2 de 3 fugas reales: **el canario es la única señal fiable**.
  - **Fase 2, no implementada (trabajo futuro):** observar el arranque de un servidor (descargas, telemetría
    inicial) y autocomprobar los subprocesos de H4/H5 con un pozo que escuche en lugar del proxy muerto.
