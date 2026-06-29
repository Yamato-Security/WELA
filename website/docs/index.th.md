---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅) สร้างโดย
<a href="https://github.com/Yamato-Security">Yamato Security</a> เป็นเครื่องมือสำหรับ
<strong>ตรวจสอบการตั้งค่า Windows event log</strong> Windows event log เป็นแหล่ง
ข้อมูลที่สำคัญสำหรับ DFIR — WELA ช่วยให้คุณมั่นใจได้ว่าคุณกำลังบันทึกเหตุการณ์ที่มีความสำคัญอย่างแท้จริง
</p>

<div class="hb-cta" markdown>
[เริ่มต้นใช้งาน :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[คู่มืออ้างอิงคำสั่ง :material-console:](commands/index.md){ .md-button }
[ดูบน GitHub :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## ทำไมต้อง WELA?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __ตรวจสอบการตั้งค่านโยบายการบันทึก log__

    ---

    ตรวจสอบ **การตั้งค่านโยบายการตรวจสอบ (audit policy)** ของ Windows event log เพื่อยืนยันว่ามีการบันทึกเหตุการณ์ที่ถูกต้อง

-   :material-book-check:{ .lg .middle } __อ้างอิงตามแนวทางมาตรฐาน__

    ---

    ตรวจสอบเทียบกับ **แนวทางการกำหนดค่าการตรวจสอบ Windows event log หลัก ๆ**

-   :material-shield-search:{ .lg .middle } __ความสามารถในการตรวจจับของ Sigma__

    ---

    ประเมินการตั้งค่าของคุณเทียบกับ **ความสามารถในการตรวจจับด้วยกฎ Sigma ในสถานการณ์จริง** — log ของคุณจะจับการโจมตีได้จริงหรือไม่?

-   :material-file-cog:{ .lg .middle } __ตรวจสอบขนาดไฟล์__

    ---

    ตรวจสอบ **ขนาดไฟล์** ของ Windows event log และแนะนำขนาดที่เหมาะสม

-   :material-cog-play:{ .lg .middle } __กำหนดค่าอัตโนมัติ__

    ---

    นำ **นโยบายการตรวจสอบและขนาดไฟล์ log ที่แนะนำ** ไปใช้ด้วยคำสั่ง `configure`

-   :material-chart-box:{ .lg .middle } __ผลลัพธ์ที่ยืดหยุ่น__

    ---

    ดูผลลัพธ์ในเทอร์มินัล, GUI, ตาราง หรือในรูปแบบ heatmap ของ **MITRE ATT&CK Navigator**

</div>

## ลิงก์ด่วน

<div class="grid cards" markdown>

-   __:material-book-open-variant: เพิ่งเริ่มต้นใช้งาน?__

    เริ่มจาก [ภาพรวม](overview/index.md) จากนั้นไปที่
    [การเริ่มต้นใช้งาน](getting-started/index.md) เพื่อติดตั้งและรัน WELA

-   __:material-console-line: กำลังใช้งานผ่าน CLI?__

    เรียกดู [รายการคำสั่ง](commands/index.md) และคู่มืออ้างอิง [การใช้งานคำสั่ง](commands/usage.md)
    (`audit-settings`, `audit-filesize`, `configure`, `update-rules`)

-   __:material-puzzle: ต้องการเรียนรู้เพิ่มเติม?__

    สำรวจ [โปรเจกต์ที่เกี่ยวข้อง](resources/companion-projects.md),
    [บันทึกการเปลี่ยนแปลง](resources/changelog.md) และวิธีการ
    [มีส่วนร่วม](resources/contributing.md)

</div>
