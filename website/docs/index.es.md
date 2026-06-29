---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), creado por
<a href="https://github.com/Yamato-Security">Yamato Security</a>, es una herramienta para
<strong>auditar la configuración de los registros de eventos de Windows</strong>. Los registros de eventos de Windows son una fuente vital de
información para DFIR — WELA te ayuda a asegurarte de que realmente estás registrando los eventos que importan.
</p>

<div class="hb-cta" markdown>
[Comenzar :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referencia de comandos :material-console:](commands/index.md){ .md-button }
[Ver en GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/WELA/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/WELA?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/WELA/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/WELA/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/WELA/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/WELA?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/WELA/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat"/></a>
<a href="https://conference.auscert.org.au/speaker/fukusuke-takahashi/"><img src="https://img.shields.io/badge/AUSCERT-2025-blue"></a>
<a href="https://www.infosec-city.com/sin-25"><img src="https://img.shields.io/badge/SINCON-2025-blue"></a>
<a href="https://codeblue.jp/program/time-table/day2-t3-02/"><img src="https://img.shields.io/badge/CODE%20BLUE-2025-blue"></a>
<a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>

</div>

---

## ¿Por qué WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Auditar la configuración de la política de registro__

    ---

    Audita la **configuración de la política de auditoría** de los registros de eventos de Windows para confirmar que se están registrando los eventos correctos.

-   :material-book-check:{ .lg .middle } __Basado en directrices__

    ---

    Comprueba según las **principales directrices de configuración de auditoría de los registros de eventos de Windows**.

-   :material-shield-search:{ .lg .middle } __Detectabilidad de Sigma__

    ---

    Evalúa tu configuración frente a la **detectabilidad de reglas Sigma del mundo real** — ¿tus registros realmente detectarán los ataques?

-   :material-file-cog:{ .lg .middle } __Auditoría del tamaño de archivos__

    ---

    Audita los **tamaños de archivo** de los registros de eventos de Windows y sugiere tamaños recomendados.

-   :material-cog-play:{ .lg .middle } __Configuración automática__

    ---

    Aplica la política de auditoría **recomendada** y los tamaños de archivo de registro con el comando `configure`.

-   :material-chart-box:{ .lg .middle } __Salida flexible__

    ---

    Visualiza los resultados en la terminal, una GUI, una tabla o como un mapa de calor de **MITRE ATT&CK Navigator**.

</div>

## Enlaces rápidos

<div class="grid cards" markdown>

-   __:material-book-open-variant: ¿Nuevo aquí?__

    Comienza con la [Descripción general](overview/index.md), luego dirígete a
    [Primeros pasos](getting-started/index.md) para instalar y ejecutar WELA.

-   __:material-console-line: ¿Trabajando con la CLI?__

    Explora la [Lista de comandos](commands/index.md) y la referencia de [Uso de comandos](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: ¿Quieres ir más allá?__

    Explora los [Proyectos complementarios](resources/companion-projects.md), el
    [Registro de cambios](resources/changelog.md), y cómo
    [contribuir](resources/contributing.md).

</div>
