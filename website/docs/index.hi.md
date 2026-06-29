---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅), जिसे
<a href="https://github.com/Yamato-Security">Yamato Security</a> द्वारा बनाया गया है, एक उपकरण है
<strong>Windows इवेंट लॉग सेटिंग्स के ऑडिट</strong> के लिए। Windows इवेंट लॉग DFIR के लिए जानकारी का
एक महत्वपूर्ण स्रोत हैं — WELA आपको यह सुनिश्चित करने में मदद करता है कि आप वास्तव में उन घटनाओं को रिकॉर्ड कर रहे हैं जो मायने रखती हैं।
</p>

<div class="hb-cta" markdown>
[शुरू करें :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[कमांड संदर्भ :material-console:](commands/index.md){ .md-button }
[GitHub पर देखें :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## WELA क्यों?

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __ऑडिट लॉग पॉलिसी सेटिंग्स__

    ---

    अपनी Windows इवेंट लॉग **ऑडिट पॉलिसी सेटिंग्स** का ऑडिट करें ताकि यह पुष्टि हो सके कि सही घटनाएं लॉग की जा रही हैं।

-   :material-book-check:{ .lg .middle } __दिशानिर्देशों पर आधारित__

    ---

    **प्रमुख Windows इवेंट लॉग ऑडिट कॉन्फ़िगरेशन दिशानिर्देशों** के विरुद्ध जांच करता है।

-   :material-shield-search:{ .lg .middle } __Sigma पहचान क्षमता__

    ---

    आपकी सेटिंग्स का **वास्तविक दुनिया की Sigma नियम पहचान क्षमता** के विरुद्ध मूल्यांकन करता है — क्या आपके लॉग वास्तव में हमलों को पकड़ पाएंगे?

-   :material-file-cog:{ .lg .middle } __फ़ाइल-आकार ऑडिटिंग__

    ---

    Windows इवेंट लॉग **फ़ाइल आकारों** का ऑडिट करता है और अनुशंसित आकार सुझाता है।

-   :material-cog-play:{ .lg .middle } __स्वतः-कॉन्फ़िगर__

    ---

    `configure` कमांड के साथ **अनुशंसित** ऑडिट पॉलिसी और लॉग फ़ाइल आकार लागू करें।

-   :material-chart-box:{ .lg .middle } __लचीला आउटपुट__

    ---

    परिणामों को टर्मिनल, GUI, टेबल, या **MITRE ATT&CK Navigator** हीटमैप के रूप में देखें।

</div>

## त्वरित लिंक

<div class="grid cards" markdown>

-   __:material-book-open-variant: यहां नए हैं?__

    [Overview](overview/index.md) से शुरू करें, फिर WELA इंस्टॉल और चलाने के लिए
    [Getting Started](getting-started/index.md) पर जाएं।

-   __:material-console-line: CLI के साथ काम कर रहे हैं?__

    [Command List](commands/index.md) और [Command Usage](commands/usage.md)
    संदर्भ ब्राउज़ करें (`audit-settings`, `audit-filesize`, `configure`, `update-rules`)।

-   __:material-puzzle: आगे बढ़ रहे हैं?__

    [Companion Projects](resources/companion-projects.md),
    [Changelog](resources/changelog.md), और
    [योगदान](resources/contributing.md) कैसे करें, इसका अन्वेषण करें।

</div>
