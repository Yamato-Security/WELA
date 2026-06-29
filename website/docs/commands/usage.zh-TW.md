# 指令使用方式
## audit-settings
`audit-settings` 指令會檢查 Windows 事件日誌的稽核原則設定，並將其與 [Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings)、[Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) 以及 [Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding) 的建議設定進行比較。
`RuleCount` 表示能夠偵測該類別中事件的 [Sigma 規則](https://github.com/SigmaHQ/sigma)數量。

### `audit-settings` 指令範例
使用預設的 Yamato Security 建議設定進行檢查，並將結果儲存為 CSV：  
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

使用 Australian Signals Directorate 的建議設定進行檢查，並將結果儲存為 CSV：  
```
./WELA.ps1 audit-settings -Baseline ASD
```

使用 Microsoft 建議的 Server OS 設定進行檢查，並以 GUI 顯示結果：  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

使用 Microsoft 建議的 Client OS 設定進行檢查，並以表格格式顯示結果：  
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize` 指令會檢查 Windows 事件日誌的檔案大小，並將其與 Yamato Security 的建議設定進行比較。

### `audit-filesize` 指令範例
使用 Yamato Security 的建議檢查 Windows 事件日誌檔案大小，並將結果儲存為 CSV：  
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure
`configure` 指令會設定建議的 Windows 事件日誌稽核原則與檔案大小。

#### `configure` 指令範例
套用 Yamato Security 的建議設定（變更設定前會出現確認提示）：
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

套用 Australian Signals Directorate 的建議設定，且不出現確認提示：
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` 指令範例
更新 WELA 的 Sigma 規則設定檔：  
```
./WELA.ps1 update-rules
```
