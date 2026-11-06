# Registro de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [0.1.0] - 2026-11-06

### Añadido
- **Núcleo del auditor** (`mrrobot.nucleo`): modelo de `Hallazgo` con severidades
  (INFO…CRITICA), carga de objetivo con **autorización explícita** (deniega por
  defecto; un host no local exige confirmación aparte) e **informe** en Markdown y
  JSON ordenado por severidad.
- **Módulo M2 — Integridad de artefactos** (`mrrobot.modulos.m2_integridad`):
  verificación SHA-256 de `.gguf` y bases vectoriales contra un manifiesto; detecta
  artefactos ausentes, alterados, sin hash de referencia y manifiestos sin firmar
  (atacantes A3 y A4 del modelo de amenazas).
- **Interfaz de línea de órdenes** `mrrobot` (y `python -m mrrobot`) con las opciones
  `--objetivo`, `--permitir-activos` y `--salida`.
- **Empaquetado instalable** con src-layout (`pip install -e .`), ejemplo de objetivo
  en `ejemplos/` y batería de pruebas con pytest.
