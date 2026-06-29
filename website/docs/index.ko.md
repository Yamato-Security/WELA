---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<a href="https://github.com/Yamato-Security">Yamato Security</a>가 만든
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅)는
<strong>Windows 이벤트 로그 설정을 감사하기</strong> 위한 도구입니다. Windows 이벤트 로그는 DFIR에 필수적인
정보 출처이며 — WELA는 여러분이 중요한 이벤트를 실제로 기록하고 있는지 확인하도록 도와줍니다.
</p>

<div class="hb-cta" markdown>
[시작하기 :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[명령어 레퍼런스 :material-console:](commands/index.md){ .md-button }
[GitHub에서 보기 :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## 왜 WELA인가?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __감사 로그 정책 설정__

    ---

    올바른 이벤트가 기록되고 있는지 확인하기 위해 Windows 이벤트 로그 **감사 정책 설정**을 감사합니다.

-   :material-book-check:{ .lg .middle } __가이드라인 기반__

    ---

    **주요 Windows 이벤트 로그 감사 구성 가이드라인**을 기준으로 점검합니다.

-   :material-shield-search:{ .lg .middle } __Sigma 탐지 가능성__

    ---

    **실제 환경의 Sigma 규칙 탐지 가능성**을 기준으로 설정을 평가합니다 — 여러분의 로그가 실제로 공격을 잡아낼 수 있을까요?

-   :material-file-cog:{ .lg .middle } __파일 크기 감사__

    ---

    Windows 이벤트 로그 **파일 크기**를 감사하고 권장 크기를 제안합니다.

-   :material-cog-play:{ .lg .middle } __자동 구성__

    ---

    `configure` 명령어로 **권장** 감사 정책과 로그 파일 크기를 적용합니다.

-   :material-chart-box:{ .lg .middle } __유연한 출력__

    ---

    결과를 터미널, GUI, 표, 또는 **MITRE ATT&CK Navigator** 히트맵으로 확인합니다.

</div>

## 빠른 링크

<div class="grid cards" markdown>

-   __:material-book-open-variant: 처음이신가요?__

    [개요](overview/index.md)로 시작한 다음,
    [시작하기](getting-started/index.md)로 이동하여 WELA를 설치하고 실행하세요.

-   __:material-console-line: CLI로 작업 중이신가요?__

    [명령어 목록](commands/index.md)과 [명령어 사용법](commands/usage.md)
    레퍼런스(`audit-settings`, `audit-filesize`, `configure`, `update-rules`)를 살펴보세요.

-   __:material-puzzle: 더 깊이 알아보시려나요?__

    [관련 프로젝트](resources/companion-projects.md),
    [변경 이력](resources/changelog.md), 그리고
    [기여하기](resources/contributing.md) 방법을 살펴보세요.

</div>
