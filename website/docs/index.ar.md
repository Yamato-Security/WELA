---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅)، الذي أنشأته
<a href="https://github.com/Yamato-Security">Yamato Security</a>، هو أداة
<strong>لتدقيق إعدادات سجل أحداث Windows</strong>. تُعد سجلات أحداث Windows مصدرًا حيويًا
للمعلومات في DFIR — يساعدك WELA على التأكد من أنك تسجل بالفعل الأحداث المهمة.
</p>

<div class="hb-cta" markdown>
[ابدأ الآن :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[مرجع الأوامر :material-console:](commands/index.md){ .md-button }
[عرض على GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## لماذا WELA؟

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __تدقيق إعدادات سياسة السجل__

    ---

    دقّق **إعدادات سياسة التدقيق** الخاصة بسجل أحداث Windows للتأكد من تسجيل الأحداث الصحيحة.

-   :material-book-check:{ .lg .middle } __مبني على الإرشادات__

    ---

    يتحقق مقابل **إرشادات تكوين تدقيق سجل أحداث Windows الرئيسية**.

-   :material-shield-search:{ .lg .middle } __قابلية الاكتشاف بواسطة Sigma__

    ---

    يقيّم إعداداتك مقابل **قابلية الاكتشاف الواقعية لقواعد Sigma** — هل ستلتقط سجلاتك الهجمات فعليًا؟

-   :material-file-cog:{ .lg .middle } __تدقيق حجم الملف__

    ---

    يدقق **أحجام ملفات** سجل أحداث Windows ويقترح الأحجام الموصى بها.

-   :material-cog-play:{ .lg .middle } __التكوين التلقائي__

    ---

    طبّق سياسة التدقيق وأحجام ملفات السجل **الموصى بها** باستخدام أمر `configure`.

-   :material-chart-box:{ .lg .middle } __مخرجات مرنة__

    ---

    اعرض النتائج في الطرفية، أو واجهة رسومية، أو جدول، أو كخريطة حرارية لـ **MITRE ATT&CK Navigator**.

</div>

## روابط سريعة

<div class="grid cards" markdown>

-   __:material-book-open-variant: جديد هنا؟__

    ابدأ بـ [نظرة عامة](overview/index.md)، ثم توجه إلى
    [البدء](getting-started/index.md) لتثبيت WELA وتشغيله.

-   __:material-console-line: تعمل مع واجهة سطر الأوامر؟__

    تصفّح [قائمة الأوامر](commands/index.md) ومرجع [استخدام الأوامر](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`).

-   __:material-puzzle: تريد المزيد؟__

    استكشف [المشاريع المصاحبة](resources/companion-projects.md)، و
    [سجل التغييرات](resources/changelog.md)، وكيفية
    [المساهمة](resources/contributing.md).

</div>
