---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), créé par
<a href="https://github.com/Yamato-Security">Yamato Security</a>, est un outil pour
<strong>auditer les paramètres des journaux d'événements Windows</strong>. Les journaux d'événements Windows sont une source d'informations essentielle
pour le DFIR — WELA vous aide à vous assurer que vous enregistrez réellement les événements qui comptent.
</p>

<div class="hb-cta" markdown>
[Commencer :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Référence des commandes :material-console:](commands/index.md){ .md-button }
[Voir sur GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Pourquoi WELA ?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Auditer les paramètres de la stratégie des journaux__

    ---

    Auditez les **paramètres de la stratégie d'audit** de vos journaux d'événements Windows pour confirmer que les bons événements sont journalisés.

-   :material-book-check:{ .lg .middle } __Basé sur des recommandations__

    ---

    Vérifie par rapport aux **principales recommandations de configuration d'audit des journaux d'événements Windows**.

-   :material-shield-search:{ .lg .middle } __Détectabilité Sigma__

    ---

    Évalue vos paramètres par rapport à la **détectabilité réelle des règles Sigma** — vos journaux détecteront-ils réellement les attaques ?

-   :material-file-cog:{ .lg .middle } __Audit de la taille des fichiers__

    ---

    Audite la **taille des fichiers** des journaux d'événements Windows et suggère des tailles recommandées.

-   :material-cog-play:{ .lg .middle } __Configuration automatique__

    ---

    Appliquez la stratégie d'audit **recommandée** et les tailles des fichiers journaux avec la commande `configure`.

-   :material-chart-box:{ .lg .middle } __Sortie flexible__

    ---

    Consultez les résultats dans le terminal, une interface graphique, un tableau, ou sous forme de carte de chaleur **MITRE ATT&CK Navigator**.

</div>

## Liens rapides

<div class="grid cards" markdown>

-   __:material-book-open-variant: Vous débutez ?__

    Commencez par l'[Aperçu](overview/index.md), puis dirigez-vous vers
    [Premiers pas](getting-started/index.md) pour installer et exécuter WELA.

-   __:material-console-line: Vous travaillez avec la CLI ?__

    Parcourez la [Liste des commandes](commands/index.md) et la référence d'[Utilisation des commandes](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Aller plus loin ?__

    Explorez les [Projets compagnons](resources/companion-projects.md), le
    [Journal des modifications](resources/changelog.md), et comment
    [contribuer](resources/contributing.md).

</div>
