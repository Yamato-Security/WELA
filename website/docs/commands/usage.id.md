# Penggunaan Perintah
## audit-settings
Perintah `audit-settings` memeriksa pengaturan kebijakan audit log peristiwa Windows dan membandingkannya dengan pengaturan yang direkomendasikan dari [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations), dan [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` menunjukkan jumlah [aturan Sigma](https://github.com/SigmaHQ/sigma) yang dapat mendeteksi peristiwa dalam kategori tersebut.

### Contoh perintah `audit-settings`
Periksa dengan pengaturan rekomendasi default Yamato Security dan simpan hasilnya ke CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Periksa dengan pengaturan rekomendasi Australian Signals Directorate dan simpan hasilnya ke CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Periksa dengan pengaturan rekomendasi Server OS dari Microsoft dan tampilkan hasilnya dalam GUI:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Periksa dengan pengaturan rekomendasi Client OS dari Microsoft dan tampilkan hasilnya dalam format tabel:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
Perintah `audit-filesize` memeriksa ukuran file log peristiwa Windows dan membandingkannya dengan pengaturan yang direkomendasikan dari rekomendasi Yamato Security.

### Contoh perintah `audit-filesize`
Periksa ukuran file log peristiwa Windows dengan rekomendasi Yamato Security dan simpan hasilnya ke CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
Perintah `configure` menetapkan kebijakan audit log peristiwa Windows dan ukuran file yang direkomendasikan.

#### Contoh perintah `configure`
Terapkan pengaturan rekomendasi Yamato Security (dengan prompt konfirmasi sebelum mengubah pengaturan):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Terapkan pengaturan rekomendasi Australian Signals Directorate tanpa prompt konfirmasi:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### Contoh perintah `update-rules`
Perbarui file konfigurasi aturan Sigma WELA:  
```
./WELA.ps1 update-rules
```
