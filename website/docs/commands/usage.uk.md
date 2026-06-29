# Використання команд
## audit-settings
Команда `audit-settings` перевіряє налаштування політики аудиту журналу подій Windows та порівнює їх із рекомендованими налаштуваннями від [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings), [Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) та [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding).
`RuleCount` вказує кількість [правил Sigma](https://github.com/SigmaHQ/sigma), які можуть виявляти події в межах цієї категорії.

### приклади команди `audit-settings`
Перевірка зі стандартними рекомендованими налаштуваннями Yamato Security та збереження результатів у CSV:  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Перевірка з рекомендованими налаштуваннями Australian Signals Directorate та збереження результатів у CSV:  
```
./WELA.ps1 audit-settings -Baseline ASD
```

Перевірка з рекомендованими налаштуваннями Microsoft для серверної ОС та відображення результатів у графічному інтерфейсі:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Перевірка з рекомендованими налаштуваннями Microsoft для клієнтської ОС та відображення результатів у форматі таблиці:  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
Команда `audit-filesize` перевіряє розмір файлів журналів подій Windows та порівнює їх із рекомендованими налаштуваннями від Yamato Security.

### приклади команди `audit-filesize`
Перевірка розміру файлу журналу подій Windows за рекомендаціями Yamato Security та збереження результатів у CSV:  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
Команда `configure` встановлює рекомендовану політику аудиту журналу подій Windows та розмір файлу.

#### приклади команди `configure`
Застосування рекомендованих налаштувань Yamato Security (з підтвердженням перед зміною налаштувань):
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Застосування рекомендованих налаштувань Australian Signals Directorate без підтвердження:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### приклади команди `update-rules`
Оновлення конфігураційних файлів правил Sigma для WELA:  
```
./WELA.ps1 update-rules
```
