---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong>（Windows Event Log Analyzer，ゑ羅）由
<a href="https://github.com/Yamato-Security">Yamato Security</a> 開發，是一款用於
<strong>稽核 Windows 事件記錄檔設定</strong>的工具。Windows 事件記錄檔是 DFIR 至關重要的
資訊來源——WELA 協助你確認自己確實記錄了重要的事件。
</p>

<div class="hb-cta" markdown>
[開始使用 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[指令參考 :material-console:](commands/index.md){ .md-button }
[在 GitHub 上檢視 :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## 為什麼選擇 WELA？

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __稽核記錄原則設定__

    ---

    稽核你的 Windows 事件記錄檔**稽核原則設定**，確認正確的事件確實有被記錄。

-   :material-book-check:{ .lg .middle } __以指南為依據__

    ---

    對照**主要的 Windows 事件記錄檔稽核設定指南**進行檢查。

-   :material-shield-search:{ .lg .middle } __Sigma 偵測能力__

    ---

    依據**真實世界的 Sigma 規則偵測能力**評估你的設定——你的記錄檔真的能捕捉到攻擊嗎？

-   :material-file-cog:{ .lg .middle } __檔案大小稽核__

    ---

    稽核 Windows 事件記錄檔的**檔案大小**並建議建議的大小。

-   :material-cog-play:{ .lg .middle } __自動設定__

    ---

    透過 `configure` 指令套用**建議的**稽核原則與記錄檔檔案大小。

-   :material-chart-box:{ .lg .middle } __彈性的輸出__

    ---

    可在終端機、GUI、表格中檢視結果，或以 **MITRE ATT&CK Navigator** 熱圖呈現。

</div>

## 快速連結

<div class="grid cards" markdown>

-   __:material-book-open-variant: 第一次使用？__

    先從[概覽](overview/index.md)開始，接著前往
    [開始使用](getting-started/index.md)來安裝並執行 WELA。

-   __:material-console-line: 在使用 CLI 嗎？__

    瀏覽[指令清單](commands/index.md)以及[指令用法](commands/usage.md)
    參考（`audit-settings`、`audit-filesize`、`configure`、`update-rules`）。

-   __:material-puzzle: 想更進一步？__

    探索[相關專案](resources/companion-projects.md)、
    [變更紀錄](resources/changelog.md)，以及如何
    [貢獻](resources/contributing.md)。

</div>
