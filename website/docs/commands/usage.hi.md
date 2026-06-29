# कमांड उपयोग
## audit-settings
`audit-settings` कमांड Windows इवेंट लॉग ऑडिट पॉलिसी सेटिंग्स की जाँच करता है और उनकी तुलना [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), और [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) की अनुशंसित सेटिंग्स से करता है।
`RuleCount` उस श्रेणी के भीतर की घटनाओं का पता लगाने में सक्षम [Sigma rules](https://github.com/SigmaHQ/sigma) की संख्या को दर्शाता है।

### `audit-settings` कमांड के उदाहरण
डिफ़ॉल्ट Yamato Security की अनुशंसित सेटिंग्स के साथ जाँचें और परिणामों को CSV में सहेजें:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Australian Signals Directorate की अनुशंसित सेटिंग्स के साथ जाँचें और परिणामों को CSV में सहेजें:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Microsoft की अनुशंसित Server OS सेटिंग्स के साथ जाँचें और परिणामों को GUI में प्रदर्शित करें:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Microsoft की अनुशंसित Client OS सेटिंग्स के साथ जाँचें और परिणामों को तालिका प्रारूप में प्रदर्शित करें:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize` कमांड Windows इवेंट लॉग्स के फ़ाइल आकार की जाँच करता है और उनकी तुलना Yamato Security की अनुशंसाओं से करता है।

### `audit-filesize` कमांड के उदाहरण
Windows इवेंट लॉग फ़ाइल आकार को Yamato Security की अनुशंसाओं के साथ जाँचें और परिणामों को CSV में सहेजें:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
`configure` कमांड अनुशंसित Windows इवेंट लॉग ऑडिट पॉलिसी और फ़ाइल आकार सेट करता है।

#### `configure` कमांड के उदाहरण
Yamato Security की अनुशंसित सेटिंग्स लागू करें (सेटिंग्स बदलने से पहले पुष्टिकरण प्रॉम्प्ट के साथ):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Australian Signals Directorate की अनुशंसित सेटिंग्स बिना पुष्टिकरण प्रॉम्प्ट के लागू करें:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` कमांड के उदाहरण
WELA की Sigma rules कॉन्फ़िग फ़ाइलों को अपडेट करें:  
```
./WELA.ps1 update-rules
```
