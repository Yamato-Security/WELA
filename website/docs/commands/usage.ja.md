# コマンド使用例
## audit-settings
`audit-settings`コマンドは、Windowsイベントログ監査ポリシー設定を評価し、[Yamato Security](https://github.com/Yamato-Security/EnableWindowsLogSettings)、[Microsoft(Sever/Client)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)、[Australian Signals Directorate (ASD)](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)の推奨設定と比較します。
RuleCountは、そのカテゴリ内のイベントを検出できる[Sigmaルール](https://github.com/SigmaHQ/sigma)の数を示します。

#### `audit-settings` command examples
YamatoSecurityの推奨設定でチェックし、CSV形式で保存する:
```
./WELA.ps1 audit-settings -Baseline YamatoSecurity
```

Australian Signals Directorateの推奨設定でチェックし、CSV形式で保存する:
```
./WELA.ps1 audit-settings -Baseline ASD
```

Microsoftの推奨設定(Server)でチェックし、GUI形式で表示する:
```
./WELA.ps1 audit-settings -Baseline Microsoft_Server -OutType gui
```

Microsoftの推奨設定(Client)でチェックし、Table形式で表示する:
```
./WELA.ps1 audit-settings -Baseline Microsoft_Client -OutType table
```

## audit-filesize
`audit-filesize`コマンドは、Windowsイベントログファイルサイズを評価し、Yamato Securityの推奨設定と比較します。

#### `audit-filesize` command examples
WindowsイベントログファイルサイズをYamatoSecurityの推奨設定でチェックし、CSV形式で保存する:
```
./WELA.ps1 audit-filesize -Baseline YamatoSecurity
```

## configure 
`configure`コマンドは、推奨のWindowsイベントログ監査ポリシーとファイルサイズを設定します。

#### `configure` command examples
Yamato Securityの推奨設定を適用する（設定変更時に確認プロンプトを表示）:
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Australian Signals Directorateの推奨設定を自動で適用する:
```
./WELA.ps1 configure -Baseline ASD -auto
```

## update-rules
#### `update-rules` command examples
WELAのSigmaルール設定ファイルを更新する:
```
./WELA.ps1 update-rules
```
