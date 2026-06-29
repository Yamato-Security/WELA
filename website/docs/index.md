---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), created by
<a href="https://github.com/Yamato-Security">Yamato Security</a>, is a tool for
<strong>auditing Windows event log settings</strong>. Windows event logs are a vital source of
information for DFIR — WELA helps you make sure you are actually recording the events that matter.
</p>

<div class="hb-cta" markdown>
[Get Started :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Command Reference :material-console:](commands/index.md){ .md-button }
[View on GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Why WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Audit log policy settings__

    ---

    Audit your Windows event log **audit policy settings** to confirm the right events are being logged.

-   :material-book-check:{ .lg .middle } __Based on guidelines__

    ---

    Checks against the **major Windows event log audit configuration guidelines**.

-   :material-shield-search:{ .lg .middle } __Sigma detectability__

    ---

    Evaluates your settings against **real-world Sigma rule detectability** — will your logs actually catch attacks?

-   :material-file-cog:{ .lg .middle } __File-size auditing__

    ---

    Audits Windows event log **file sizes** and suggests recommended sizes.

-   :material-cog-play:{ .lg .middle } __Auto-configure__

    ---

    Apply the **recommended** audit policy and log file sizes with the `configure` command.

-   :material-chart-box:{ .lg .middle } __Flexible output__

    ---

    View results in the terminal, a GUI, a table, or as a **MITRE ATT&CK Navigator** heatmap.

</div>

## Quick links

<div class="grid cards" markdown>

-   __:material-book-open-variant: New here?__

    Start with the [Overview](overview/index.md), then head to
    [Getting Started](getting-started/index.md) to install and run WELA.

-   __:material-console-line: Working with the CLI?__

    Browse the [Command List](commands/index.md) and the [Command Usage](commands/usage.md)
    reference (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Going further?__

    Explore the [Companion Projects](resources/companion-projects.md), the
    [Changelog](resources/changelog.md), and how to
    [contribute](resources/contributing.md).

</div>
