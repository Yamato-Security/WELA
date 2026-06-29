---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), erstellt von
<a href="https://github.com/Yamato-Security">Yamato Security</a>, ist ein Werkzeug zum
<strong>Überprüfen von Windows-Ereignisprotokolleinstellungen</strong>. Windows-Ereignisprotokolle sind eine entscheidende Informationsquelle
für DFIR — WELA hilft Ihnen sicherzustellen, dass Sie tatsächlich die Ereignisse aufzeichnen, die wichtig sind.
</p>

<div class="hb-cta" markdown>
[Erste Schritte :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Befehlsreferenz :material-console:](commands/index.md){ .md-button }
[Auf GitHub ansehen :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Warum WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Überwachungsrichtlinieneinstellungen prüfen__

    ---

    Überprüfen Sie die **Überwachungsrichtlinieneinstellungen** Ihrer Windows-Ereignisprotokolle, um zu bestätigen, dass die richtigen Ereignisse protokolliert werden.

-   :material-book-check:{ .lg .middle } __Auf Richtlinien basierend__

    ---

    Prüft anhand der **wichtigsten Konfigurationsrichtlinien für die Überwachung von Windows-Ereignisprotokollen**.

-   :material-shield-search:{ .lg .middle } __Sigma-Erkennbarkeit__

    ---

    Bewertet Ihre Einstellungen anhand der **realen Erkennbarkeit durch Sigma-Regeln** — werden Ihre Protokolle Angriffe tatsächlich erfassen?

-   :material-file-cog:{ .lg .middle } __Dateigrößenprüfung__

    ---

    Prüft die **Dateigrößen** von Windows-Ereignisprotokollen und schlägt empfohlene Größen vor.

-   :material-cog-play:{ .lg .middle } __Automatische Konfiguration__

    ---

    Wenden Sie die **empfohlene** Überwachungsrichtlinie und Protokolldateigrößen mit dem Befehl `configure` an.

-   :material-chart-box:{ .lg .middle } __Flexible Ausgabe__

    ---

    Sehen Sie sich die Ergebnisse im Terminal, in einer GUI, in einer Tabelle oder als **MITRE ATT&CK Navigator**-Heatmap an.

</div>

## Schnelllinks

<div class="grid cards" markdown>

-   __:material-book-open-variant: Neu hier?__

    Beginnen Sie mit der [Übersicht](overview/index.md) und gehen Sie dann zu den
    [Ersten Schritten](getting-started/index.md), um WELA zu installieren und auszuführen.

-   __:material-console-line: Arbeiten Sie mit der CLI?__

    Durchsuchen Sie die [Befehlsliste](commands/index.md) und die Referenz zur [Befehlsverwendung](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Gehen Sie weiter?__

    Erkunden Sie die [Begleitprojekte](resources/companion-projects.md), das
    [Änderungsprotokoll](resources/changelog.md) und wie Sie
    [beitragen](resources/contributing.md) können.

</div>
