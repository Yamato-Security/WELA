---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<a href="https://github.com/Yamato-Security">Yamato Security</a> tarafından oluşturulan
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅),
<strong>Windows olay günlüğü ayarlarını denetlemek</strong> için bir araçtır. Windows olay günlükleri DFIR için hayati bir
bilgi kaynağıdır — WELA, önemli olayları gerçekten kaydettiğinizden emin olmanıza yardımcı olur.
</p>

<div class="hb-cta" markdown>
[Başlayın :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Komut Referansı :material-console:](commands/index.md){ .md-button }
[GitHub'da Görüntüle :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## Neden WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Günlük ilkesi ayarlarını denetleyin__

    ---

    Doğru olayların günlüğe kaydedildiğini doğrulamak için Windows olay günlüğü **denetim ilkesi ayarlarınızı** denetleyin.

-   :material-book-check:{ .lg .middle } __Yönergelere dayalı__

    ---

    **Başlıca Windows olay günlüğü denetim yapılandırma yönergelerine** karşı kontrol eder.

-   :material-shield-search:{ .lg .middle } __Sigma tespit edilebilirliği__

    ---

    Ayarlarınızı **gerçek dünya Sigma kuralı tespit edilebilirliğine** karşı değerlendirir — günlükleriniz saldırıları gerçekten yakalayacak mı?

-   :material-file-cog:{ .lg .middle } __Dosya boyutu denetimi__

    ---

    Windows olay günlüğü **dosya boyutlarını** denetler ve önerilen boyutları önerir.

-   :material-cog-play:{ .lg .middle } __Otomatik yapılandırma__

    ---

    `configure` komutuyla **önerilen** denetim ilkesini ve günlük dosyası boyutlarını uygulayın.

-   :material-chart-box:{ .lg .middle } __Esnek çıktı__

    ---

    Sonuçları terminalde, bir GUI'de, bir tabloda veya bir **MITRE ATT&CK Navigator** ısı haritası olarak görüntüleyin.

</div>

## Hızlı bağlantılar

<div class="grid cards" markdown>

-   __:material-book-open-variant: Buraya yeni mi geldiniz?__

    [Genel Bakış](overview/index.md) ile başlayın, ardından WELA'yı kurmak ve çalıştırmak için
    [Başlangıç](getting-started/index.md) bölümüne geçin.

-   __:material-console-line: CLI ile mi çalışıyorsunuz?__

    [Komut Listesi](commands/index.md) ve [Komut Kullanımı](commands/usage.md)
    referansına göz atın (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: Daha ileri mi gidiyorsunuz?__

    [Tamamlayıcı Projeleri](resources/companion-projects.md),
    [Değişiklik Günlüğünü](resources/changelog.md) ve nasıl
    [katkıda bulunabileceğinizi](resources/contributing.md) keşfedin.

</div>
