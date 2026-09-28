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

## audit-filesize と configure-eventlogs

`audit-filesize` は、設定と共通のプロファイルを使ってイベントログの実際の
サイズと保存方式を読み取り、正確なバイト数を CSV に保存します。
利用できる `-LogProfile` は `eventlog-profiles` で一覧表示できます。
詳細監査ポリシーを選択する `-Profile` とは別の設定です。

```powershell
./WELA.ps1 audit-filesize -LogProfile wela-source-2.2.0
./WELA.ps1 configure-eventlogs -LogProfile asd-source-2021-10 -DryRun
./WELA.ps1 configure-eventlogs -LogProfile asd-collector-archive-2021-10 -ApplyLogMode
```

`configure-eventlogs` は、既定では現在より大きいバッファと現在の保存方式を保持します。
`-ResizeLogs` は縮小を明示的に許可し、`-ApplyLogMode` は送信元の循環方式または
収集サーバーのアーカイブ方式を明示的に適用します。保存日数はイベント量と
アーカイブ保存期間を測定するまで不明です。

## configure 
`configure` は、ネイティブログ制御または選択した詳細監査ポリシープロファイルを
適用します。イベントログのサイズと保存方式は `configure-eventlogs` で個別に設定します。

#### `configure` command examples
Yamato Securityの推奨設定を適用する（設定変更時に確認プロンプトを表示）:
```
./WELA.ps1 configure -Baseline YamatoSecurity
```

Windows クライアント向け Australian Signals Directorate ネイティブ監査プロファイルを
事前確認してから、確認プロンプトなしで適用する:

```powershell
./WELA.ps1 configure -Profile asd-native-2021-10 -Role Client -Build 26100 -DryRun
./WELA.ps1 configure -Profile asd-native-2021-10 -Role Client -Build 26100 -Auto
```

従来の `configure -Baseline` で指定できるのは `YamatoSecurity` だけです。
ASD、Microsoft、CIS、その他のバージョン付き詳細監査プロファイルには `-Profile` を使用し、
利用できる ID は `./WELA.ps1 profiles` で確認してください。

## update-rules
#### `update-rules` command examples
WELAのSigmaルール設定ファイルを更新する:
```
./WELA.ps1 update-rules
```
