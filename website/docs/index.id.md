---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), dibuat oleh
<a href="https://github.com/Yamato-Security">Yamato Security</a>, adalah alat untuk
<strong>mengaudit pengaturan log peristiwa Windows</strong>. Log peristiwa Windows merupakan sumber
informasi yang vital bagi DFIR — WELA membantu Anda memastikan bahwa Anda benar-benar merekam peristiwa yang penting.
</p>

<div class="hb-cta" markdown>
[Mulai :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Referensi Perintah :material-console:](commands/index.md){ .md-button }
[Lihat di GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Mengapa WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Audit pengaturan kebijakan log__

    ---

    Audit **pengaturan kebijakan audit** log peristiwa Windows Anda untuk memastikan peristiwa yang tepat sedang dicatat.

-   :material-book-check:{ .lg .middle } __Berdasarkan pedoman__

    ---

    Memeriksa terhadap **pedoman konfigurasi audit log peristiwa Windows yang utama**.

-   :material-shield-search:{ .lg .middle } __Keterdeteksian Sigma__

    ---

    Mengevaluasi pengaturan Anda terhadap **keterdeteksian aturan Sigma di dunia nyata** — apakah log Anda benar-benar akan menangkap serangan?

-   :material-file-cog:{ .lg .middle } __Audit ukuran file__

    ---

    Mengaudit **ukuran file** log peristiwa Windows dan menyarankan ukuran yang direkomendasikan.

-   :material-cog-play:{ .lg .middle } __Konfigurasi otomatis__

    ---

    Terapkan kebijakan audit dan ukuran file log yang **direkomendasikan** dengan perintah `configure`.

-   :material-chart-box:{ .lg .middle } __Keluaran fleksibel__

    ---

    Lihat hasil di terminal, GUI, tabel, atau sebagai peta panas **MITRE ATT&CK Navigator**.

</div>

## Tautan cepat

<div class="grid cards" markdown>

-   __:material-book-open-variant: Baru di sini?__

    Mulai dengan [Ikhtisar](overview/index.md), lalu lanjut ke
    [Memulai](getting-started/index.md) untuk memasang dan menjalankan WELA.

-   __:material-console-line: Bekerja dengan CLI?__

    Telusuri [Daftar Perintah](commands/index.md) dan referensi [Penggunaan Perintah](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Ingin lebih jauh?__

    Jelajahi [Proyek Pendamping](resources/companion-projects.md),
    [Changelog](resources/changelog.md), dan cara
    [berkontribusi](resources/contributing.md).

</div>
