# Command အသုံးပြုပုံ
## audit-settings
`audit-settings` command သည် Windows event log audit policy settings များကို စစ်ဆေးပြီး [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings)၊ [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) နှင့် [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) တို့မှ အကြံပြုထားသော settings များနှင့် နှိုင်းယှဉ်ပေးပါသည်။
`RuleCount` သည် ထို category အတွင်းရှိ events များကို ရှာဖွေတွေ့ရှိနိုင်သော [Sigma rules](https://github.com/SigmaHQ/sigma) အရေအတွက်ကို ဖော်ပြသည်။

### `audit-settings` command နမူနာများ
ပုံသေ Yamato Security ၏ အကြံပြုထားသော settings များဖြင့် စစ်ဆေးပြီး ရလဒ်များကို CSV သို့ သိမ်းဆည်းရန်-  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Australian Signals Directorate ၏ အကြံပြုထားသော settings များဖြင့် စစ်ဆေးပြီး ရလဒ်များကို CSV သို့ သိမ်းဆည်းရန်-  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Microsoft ၏ အကြံပြုထားသော Server OS settings များဖြင့် စစ်ဆေးပြီး ရလဒ်များကို GUI တွင် ပြသရန်-  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Microsoft ၏ အကြံပြုထားသော Client OS settings များဖြင့် စစ်ဆေးပြီး ရလဒ်များကို table format ဖြင့် ပြသရန်-  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize` command သည် Windows event logs များ၏ file size ကို စစ်ဆေးပြီး Yamato Security ၏ အကြံပြုချက်များမှ အကြံပြုထားသော settings များနှင့် နှိုင်းယှဉ်ပေးပါသည်။

### `audit-filesize` command နမူနာများ
Windows event log file size ကို Yamato Security ၏ အကြံပြုချက်များဖြင့် စစ်ဆေးပြီး ရလဒ်များကို CSV သို့ သိမ်းဆည်းရန်-  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
`configure` command သည် အကြံပြုထားသော Windows event log audit policy နှင့် file size ကို သတ်မှတ်ပေးပါသည်။

#### `configure` command နမူနာများ
Yamato Security ၏ အကြံပြုထားသော settings များကို အသုံးချရန် (settings များ ပြောင်းလဲမည့်အကြိုတွင် အတည်ပြုချက် prompt ဖြင့်)-
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Australian Signals Directorate ၏ အကြံပြုထားသော settings များကို အတည်ပြုချက် prompt မပါဘဲ အသုံးချရန်-
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` command နမူနာများ
WELA ၏ Sigma rules config files များကို update လုပ်ရန်-  
```
./WELA.ps1 update-rules
```
