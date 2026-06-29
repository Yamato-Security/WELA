# Komut Kullanımı
## audit-settings
`audit-settings` komutu, Windows olay günlüğü denetim ilkesi ayarlarını kontrol eder ve bunları [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) ve [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) tarafından önerilen ayarlarla karşılaştırır.
`RuleCount`, o kategorideki olayları tespit edebilen [Sigma kurallarının](https://github.com/SigmaHQ/sigma) sayısını gösterir.

### `audit-settings` komut örnekleri
Varsayılan Yamato Security'nin önerilen ayarlarıyla kontrol edin ve sonuçları CSV'ye kaydedin:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Australian Signals Directorate'in önerilen ayarlarıyla kontrol edin ve sonuçları CSV'ye kaydedin:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Microsoft'un önerilen Sunucu OS ayarlarıyla kontrol edin ve sonuçları bir GUI'de görüntüleyin:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Microsoft'un önerilen İstemci OS ayarlarıyla kontrol edin ve sonuçları tablo biçiminde görüntüleyin:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize` komutu, Windows olay günlüklerinin dosya boyutunu kontrol eder ve bunları Yamato Security'nin önerileriyle karşılaştırır.

### `audit-filesize` komut örnekleri
Windows olay günlüğü dosya boyutunu Yamato Security'nin önerileriyle kontrol edin ve sonuçları CSV'ye kaydedin:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
`configure` komutu, önerilen Windows olay günlüğü denetim ilkesini ve dosya boyutunu ayarlar.

#### `configure` komut örnekleri
Yamato Security'nin önerilen ayarlarını uygulayın (ayarları değiştirmeden önce onay istemiyle):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Australian Signals Directorate'in önerilen ayarlarını onay istemi olmadan uygulayın:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` komut örnekleri
WELA'nın Sigma kuralları yapılandırma dosyalarını güncelleyin:  
```
./WELA.ps1 update-rules
```
