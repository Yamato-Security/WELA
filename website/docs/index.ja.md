---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong>（Windows Event Log Analyzer、ゑ羅）は、
<a href="https://github.com/Yamato-Security">Yamato Security</a> によって作られた、
<strong>Windows イベントログの設定を監査する</strong>ためのツールです。Windows イベントログは
DFIR における重要な情報源です。WELA は、本当に必要なイベントが記録されているかを確認するのに役立ちます。
</p>

<div class="hb-cta" markdown>
[はじめる :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[コマンド一覧 :material-console:](commands/index.md){ .md-button }
[GitHub で見る :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## WELA の特徴

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __監査ポリシー設定の監査__

    ---

    Windows イベントログの**監査ポリシー設定**を監査し、必要なイベントが記録されているか確認します。

-   :material-book-check:{ .lg .middle } __ガイドラインに基づく確認__

    ---

    主要な Windows イベントログ監査設定の**ガイドライン**に基づいてチェックします。

-   :material-shield-search:{ .lg .middle } __Sigma 検知可能性__

    ---

    実際の **Sigma ルールの検知可能性**に基づいて設定を評価します。ログで攻撃を検知できますか？

-   :material-file-cog:{ .lg .middle } __ファイルサイズの監査__

    ---

    Windows イベントログの**ファイルサイズ**を監査し、推奨サイズを提案します。

-   :material-cog-play:{ .lg .middle } __自動設定__

    ---

    `configure` コマンドで、**推奨**の監査ポリシーとログファイルサイズを適用します。

-   :material-chart-box:{ .lg .middle } __柔軟な出力__

    ---

    結果をターミナル・GUI・テーブル、または **MITRE ATT&CK Navigator** のヒートマップで表示できます。

</div>

## クイックリンク

<div class="grid cards" markdown>

-   __:material-book-open-variant: はじめての方へ__

    まずは[概要](overview/index.md)を読み、[はじめる](getting-started/index.md)で
    WELA のインストールと実行を行いましょう。

-   __:material-console-line: CLI を使う__

    [コマンド一覧](commands/index.md)と[コマンド使用例](commands/usage.md)
    （`audit-settings`・`audit-filesize`・`configure`・`update-rules`）をご覧ください。

-   __:material-puzzle: さらに活用する__

    [関連プロジェクト](resources/companion-projects.md)、[変更履歴](resources/changelog.md)、
    [貢献方法](resources/contributing.md)を見てみましょう。

</div>
