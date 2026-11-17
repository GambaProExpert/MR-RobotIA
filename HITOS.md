# MRRobotIA — Hitos (roadmap por capas)

> Operativiza [Guia_agentes.md](Guia_agentes.md). Alcance elegido: **LLM + RAG + host**.
> Estado de este documento: versión 0.10.0 (2026-11-17). H0-H4 hechos; H5-H7 por hacer (H7 con el diseño hecho). vLLM está validado contra un
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
| **H5 · Prompt injection / evals** | 2 | **promptfoo** | red team + evals en YAML como *gate* de CI: inyección directa e indirecta, fuga entre sesiones, agencia excesiva, BOLA/BFLA | por hacer |
| **H6 · Datos no salen de la red** | 2 | **DeepEval / DeepTeam** | **MUY IMPORTANTE**: comprobar que prompts y salidas no salen de la red; juez local (`deepeval set-ollama`), red teaming offline | por hacer |
| **H7 · Simulación de ataques con verificación** | 2 | código propio + **Schemathesis** y **vegeta** opcionales | ataques inocuos y acotados contra el servidor (o la pasarela o aplicación de delante) y, por cada uno: ¿se bloqueó?, ¿quedó constancia (logs, métricas, auditoría)?, ¿se recuperó el servidor? Remedio y repetición de lo que falló | por hacer (diseño hecho; ver abajo) |
| Capa 3 · agentes, MCP, herramientas | 3 | agentic-radar, etc. | superficie de agentes/MCP | **más adelante** (fuera de alcance ahora) |

## Orden propuesto

`H0 → H2 → H3 → H4 → H5 → H6 → H7`

- **H0, H2 y H3 no dependen** de instalar garak/promptfoo/DeepEval: son el cimiento y la Capa 1.
- **H4–H6** sí requieren esas herramientas en local; se abordan después del núcleo.
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
  propio de una aplicación, con sus canarios) queda para H5 (promptfoo) o una sonda propia de garak.
