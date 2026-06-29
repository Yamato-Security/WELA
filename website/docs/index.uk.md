---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), створений
<a href="https://github.com/Yamato-Security">Yamato Security</a>, — це інструмент для
<strong>аудиту налаштувань журналу подій Windows</strong>. Журнали подій Windows є життєво важливим джерелом
інформації для DFIR — WELA допомагає переконатися, що ви дійсно записуєте події, які мають значення.
</p>

<div class="hb-cta" markdown>
[Почати роботу :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Довідник команд :material-console:](commands/index.md){ .md-button }
[Переглянути на GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Чому WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Аудит налаштувань політики журналювання__

    ---

    Перевіряйте **налаштування політики аудиту** журналу подій Windows, щоб підтвердити, що журналюються правильні події.

-   :material-book-check:{ .lg .middle } __На основі рекомендацій__

    ---

    Перевірка відповідно до **основних рекомендацій з налаштування аудиту журналу подій Windows**.

-   :material-shield-search:{ .lg .middle } __Виявлюваність Sigma__

    ---

    Оцінює ваші налаштування за **реальною виявлюваністю правил Sigma** — чи дійсно ваші журнали виявлятимуть атаки?

-   :material-file-cog:{ .lg .middle } __Аудит розміру файлів__

    ---

    Перевіряє **розміри файлів** журналу подій Windows та пропонує рекомендовані розміри.

-   :material-cog-play:{ .lg .middle } __Автоматичне налаштування__

    ---

    Застосовуйте **рекомендовану** політику аудиту та розміри файлів журналу за допомогою команди `configure`.

-   :material-chart-box:{ .lg .middle } __Гнучкий вивід__

    ---

    Переглядайте результати в терміналі, графічному інтерфейсі, у вигляді таблиці або як теплову карту **MITRE ATT&CK Navigator**.

</div>

## Швидкі посилання

<div class="grid cards" markdown>

-   __:material-book-open-variant: Уперше тут?__

    Почніть з [Огляду](overview/index.md), а потім перейдіть до
    [Початку роботи](getting-started/index.md), щоб встановити та запустити WELA.

-   __:material-console-line: Працюєте з CLI?__

    Перегляньте [Список команд](commands/index.md) та довідник
    [Використання команд](commands/usage.md) (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Хочете більше?__

    Ознайомтеся із [Супутніми проєктами](resources/companion-projects.md),
    [Журналом змін](resources/changelog.md) та тим, як
    [зробити внесок](resources/contributing.md).

</div>
