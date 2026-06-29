---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

![WELA](assets/screenshots/WELA-Logo.png){ .hb-logo }

<p class="hb-tagline">
<strong>WELA</strong> (Windows Event Log Analyzer, ゑ羅) ကို
<a href="https://github.com/Yamato-Security">Yamato Security</a> မှ ဖန်တီးထားပြီး၊ ၎င်းသည်
<strong>Windows event log ဆက်တင်များကို စစ်ဆေးအတည်ပြုခြင်း</strong> အတွက် ကိရိယာတစ်ခုဖြစ်သည်။ Windows event log များသည် DFIR အတွက် အရေးကြီးသော
သတင်းအချက်အလက် ရင်းမြစ်တစ်ခုဖြစ်ပြီး — WELA သည် အရေးပါသော အဖြစ်အပျက်များကို သင်အမှန်တကယ် မှတ်တမ်းတင်နေကြောင်း သေချာစေရန် ကူညီပေးသည်။
</p>

<div class="hb-cta" markdown>
[စတင်အသုံးပြုရန် :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Command အကိုးအကား :material-console:](commands/index.md){ .md-button }
[GitHub တွင်ကြည့်ရှုရန် :fontawesome-brands-github:](https://github.com/Yamato-Security/WELA){ .md-button }
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

## WELA ကို ဘာကြောင့်ရွေးချယ်သင့်သနည်း။

<div class="grid cards" markdown>

-   :material-clipboard-check:{ .lg .middle } __Log policy ဆက်တင်များကို စစ်ဆေးခြင်း__

    ---

    မှန်ကန်သော အဖြစ်အပျက်များကို မှတ်တမ်းတင်နေကြောင်း အတည်ပြုရန် သင်၏ Windows event log **audit policy ဆက်တင်များ** ကို စစ်ဆေးပါ။

-   :material-book-check:{ .lg .middle } __လမ်းညွှန်ချက်များအပေါ် အခြေခံထားသည်__

    ---

    **အဓိက Windows event log audit configuration လမ်းညွှန်ချက်များ** နှင့်ညှိနှိုင်း၍ စစ်ဆေးပေးသည်။

-   :material-shield-search:{ .lg .middle } __Sigma ဖြင့် ထောက်လှမ်းနိုင်စွမ်း__

    ---

    သင်၏ ဆက်တင်များကို **လက်တွေ့ကမ္ဘာ Sigma rule ထောက်လှမ်းနိုင်စွမ်း** နှင့်ညှိနှိုင်း၍ အကဲဖြတ်ပေးသည် — သင်၏ log များသည် တိုက်ခိုက်မှုများကို အမှန်တကယ် ဖမ်းမိနိုင်ပါမည်လား။

-   :material-file-cog:{ .lg .middle } __ဖိုင်အရွယ်အစား စစ်ဆေးခြင်း__

    ---

    Windows event log **ဖိုင်အရွယ်အစားများ** ကို စစ်ဆေးပြီး အကြံပြုထားသော အရွယ်အစားများကို အကြံပြုပေးသည်။

-   :material-cog-play:{ .lg .middle } __အလိုအလျောက် configure ပြုလုပ်ခြင်း__

    ---

    **အကြံပြုထားသော** audit policy နှင့် log ဖိုင်အရွယ်အစားများကို `configure` command ဖြင့် အသုံးပြုပါ။

-   :material-chart-box:{ .lg .middle } __ပြောင်းလွယ်ပြင်လွယ် output__

    ---

    ရလဒ်များကို terminal၊ GUI၊ table တွင် သို့မဟုတ် **MITRE ATT&CK Navigator** heatmap အဖြစ် ကြည့်ရှုပါ။

</div>

## အမြန်လင့်ခ်များ

<div class="grid cards" markdown>

-   __:material-book-open-variant: ဤနေရာတွင် အသစ်လား။__

    [Overview](overview/index.md) ဖြင့် စတင်ပြီးနောက် WELA ကို install ပြုလုပ်၍ run ရန်
    [Getting Started](getting-started/index.md) သို့ ဆက်သွားပါ။

-   __:material-console-line: CLI ဖြင့် အလုပ်လုပ်နေပါသလား။__

    [Command List](commands/index.md) နှင့် [Command Usage](commands/usage.md)
    အကိုးအကား (`audit-settings`, `audit-filesize`, `configure`, `update-rules`) ကို လှော်လှန်ကြည့်ပါ။

-   __:material-puzzle: ပိုမိုဆက်လက်လေ့လာမည်လား။__

    [Companion Projects](resources/companion-projects.md)၊
    [Changelog](resources/changelog.md) နှင့်
    [contribute](resources/contributing.md) ပြုလုပ်နည်းကို လေ့လာပါ။

</div>
