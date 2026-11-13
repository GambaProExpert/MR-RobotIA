# MRRobotIA — Hitos (roadmap por capas)

> Operativiza [Guia_agentes.md](Guia_agentes.md). Alcance elegido: **LLM + RAG + host**.
> Estado de este documento: versión 0.6.0 (2026-11-09). H0-H3 hechos; H4-H6 por hacer. Queda pendiente la
> **validación real de vLLM** (ver más abajo).

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
| **H2 · Identificación, exposición, arranque y avisos** | 1 | código propio (+ Julius opcional) | **H2-ID** identifica antes de auditar el servidor (llama.cpp o vLLM), versión, arranque y SO; **H2** evalúa por servidor *bind* (loopback vs `0.0.0.0`), autenticación, CORS, `Host`, TLS y los endpoints propios del perfil; **H2-ARRANQUE** revisa opciones y entorno; **H2-CVE** compara la versión con 48 avisos de llama.cpp y 140 de vLLM. Puertos por defecto de llama.cpp: **9931** (builds recientes) y **8080**; de vLLM, 8000 | **hecho** · llama.cpp validado contra un servidor real; **vLLM implementado desde el código de la 0.33.0, sin validar contra un servidor real** |
| **H3 · Seguridad del host** | 1 | código propio + **Trivy** + ssh-audit | SSH (`sshd_config` CIS + `ssh-audit`), puertos abiertos innecesarios/inseguros (los puertos esperados salen de lo identificado) y vulnerabilidades/secretos/config con Trivy. Solo se ejecuta en máquinas con un servidor llama.cpp o vLLM. | **hecho** · Trivy y ssh-audit solo con salidas simuladas |
| **H4 · Barrido del endpoint** | 2 | **garak** (NVIDIA) | barrido amplio del endpoint REST/llama.cpp (sondas de inyección y más) → informe JSONL normalizado | por hacer (sustituirá a un prober propio previo, fuera del repositorio) |
| **H5 · Prompt injection / evals** | 2 | **promptfoo** | red team + evals en YAML como *gate* de CI: inyección directa e indirecta, fuga entre sesiones, agencia excesiva, BOLA/BFLA | por hacer |
| **H6 · Datos no salen de la red** | 2 | **DeepEval / DeepTeam** | **MUY IMPORTANTE**: comprobar que prompts y salidas no salen de la red; juez local (`deepeval set-ollama`), red teaming offline | por hacer |
| Capa 3 · agentes, MCP, herramientas | 3 | agentic-radar, etc. | superficie de agentes/MCP | **más adelante** (fuera de alcance ahora) |

## Orden propuesto

`H0 → H2 → H3 → H4 → H5 → H6`

- **H0, H2 y H3 no dependen** de instalar garak/promptfoo/DeepEval: son el cimiento y la Capa 1.
- **H4–H6** sí requieren esas herramientas en local; se abordan después del núcleo.

## Qué declara cada hito (a rellenar con savvy-flow)

Para cada hito, la investigación debe fijar: instalación **local y offline**; comando exacto
contra un endpoint **llama.cpp**; formato de salida y su parseo; mapeo a severidad + marcos
(OWASP·ATLAS·NIST); si es módulo **activo** o pasivo; y pruebas sin red ni modelo.

## Estado del repositorio

- Hecho: núcleo (`nucleo.py`, `herramientas.py`), identificación y perfiles, H1/M2, M3 de
  configuración (se integra en H2 para aplicaciones con login), H2 completo y H3.
- Selector del comando: `--scan`, `--skip`, `--list`, `--server` y `--declared-only` (opciones cortas e inglesas desde la 0.7.0).
- **Pendiente de validar:** vLLM contra un servidor real (hoy solo el servidor falso que sigue la
  lectura del código de la 0.33.0), y Trivy y ssh-audit instalados de verdad.
- Pendiente de decidir en H4: qué se hace con un prober propio anterior, que no forma parte de
  esta versión y cuyo cometido asumirá garak.
