# CHANGELOG

## 2.2.0 [2026/xx/xx] - Dev Release

**改善:**

- ネイティブのDomain/Private/Publicテキストログを監査・計画・設定する任意実行の`firewall-logging`を追加しました。許可・破棄ログの有効化、最小サイズの確認、既存パスと大きな上限値の保持、CIS v4.0.0のパスの明示的な選択に対応します。ファイアウォールサービスのディレクトリ権限を確認し、ローカル設定と実効設定を記録して変更後の実効設定を検証します。通信制御やACLは変更しません。実通信によるログ生成と収集の検証は別途必要です。 (#394) (@Shirofune-Security)
- イベントログのサイズ監査と設定に共通のバイト単位プロファイルを導入し、AppLocker・ファイアウォールログの256 MiB、Setupの32 MiB、ASD推奨のSecurityログ2048 MiBに対応した。`-LogProfile`と`configure-eventlogs`で送信元と収集サーバーのサイズ・保存方式を選択できる。明示的に指定しない限り、既存の大きいバッファと保存方式は維持する。結果には検証した設定を記録し、未測定の保存日数は不明と表示する。 (#396) (@Shirofune-Security)

- 6つのネイティブSMB監査ポリシーを監査・計画・設定する任意実行の`smb-auditing`を追加しました。OSビルドとローカルADMXの正確な定義を確認してから書き込み、ポリシーのDWORD値と取得可能な実行時設定を分けて表示します。Dry-run、復旧用記録、ポリシーレジストリの検証に対応します。実行時設定は有効・検証待ち・不明を区別し、Falseが観測されてもレジストリへの書き込み成功を失敗とは扱いません。署名・暗号化要件やゲストアクセスは変更しません。実イベント生成と収集の検証は別途必要です。 (#397) (@Shirofune-Security)
- `audit-settings`、`plan`、`configure`で共有するバージョン付きの詳細監査ポリシープロファイルを追加した。59のサブカテゴリと14のプロファイルで、WELA、文書に基づくWindows既定値、Microsoft、確認済みのCIS v4.0.0、ASDのWindows標準機能向け監査ガイドに対応する。ホストの役割とビルドの検証、オフラインでの設定計画、出典と前提条件を含むJSON出力をサポートする。完全一致、最低限、任意、変更なし、未構成、適用対象外を区別する。Windows既定値は参照専用で、プロファイルの対象はSecurityログの詳細監査ポリシーに限定される。 (#390) (@Shirofune-Security)
- WELAのプロファイルにWindows標準の監査サブカテゴリを6つ追加した。Group MembershipとAuthorization Policy Changeは成功、Application Group Management、MPSSVC Rule-Level Policy Change、IPsec Driver、Kernel Objectは成功と失敗を監査する。各ガイドに対応するプロファイルでは、それぞれの監査設定と前提条件を維持する。Kernel Objectのイベント生成には対象オブジェクトに適切なSACLが必要であり、この変更ではそのSACLを作成しない。 (#391) (@Shirofune-Security)
- `configure`と`configure -Profile`に`-DryRun`と`-ResultsPath`を追加し、Windows設定を変更せずに変更内容を確認し、設定項目ごとの結果をJSONで出力できるようにした。`-DryRun`に対応していないコマンドは、実行前にエラーで停止する。 (#392) (@Shirofune-Security)
- `-BackupPath`と、各設定項目の変更前の状態を記録する復旧用ジャーナルを追加し、手動での復旧手順を文書化した。 (#392) (@Shirofune-Security)
- ベースライン定義を`WELA.ps1`から`config/baselines.json`に外部化し、ベースラインの追加・変更をJSONの編集のみで行えるようにした。 (#358) (@fukusuket)
- `Microsoft-Windows-DFSN-Server/Admin`チャネルを`audit-settings`と`audit-filesize`の確認対象に追加した。 (#358) (@fukusuket)
- MITRE ATT&CK Navigatorのヒートマップを ATT&CK v19 に対応させ、ATT&CK側でrevokedとなった技術IDを置換先に書き換えるようにした(例: v19で`T1685`に統合された`T1562`と`T1562.001`)。Navigatorはrevokedのエントリを黙って破棄するため、従来はその分のカバレッジがヒートマップから欠落していた。 (@fukusuket)

**バグ修正:**

- 通常の`configure`と`configure -Profile`で、詳細監査サブカテゴリを適用する前に`SCENoApplyLegacyAuditPolicy=1` (DWORD)の変更前の状態を記録し、設定後の値を検証するようにした。前提設定の変更に失敗した場合や変更を拒否した場合は、依存する書き込みを行わない。書き込み直前と最終確認で設定の変化を検出し、プロファイルの計画には現在の状態と取得可能な最終適用RSoP情報を含める。ポリシー更新後の永続性は保証しない。 (#393) (@Shirofune-Security)
- Windows標準チャネルを一律に`Enabled`と表示していた処理を、実際の有効状態・ログモード・ACLの読み取りとプロバイダーの前提条件の確認に置き換えた。AppLocker、NTLM、Defenderなどのイベント生成は検証されるまで条件付きとし、チャネルが有効なだけではルールを利用可能と判定しない。アクセス拒否・未登録の状態とソースの確認結果を保持するJSON/HTML監査レポート出力を追加した。ルールのチャネルパターンを具体的なカタログのチャネル名と照合する処理を、ルールの絞り込みとソースの対応付けで統一した。 (#395) (@Shirofune-Security)
- `configure`が既定で送信NTLM認証をブロックしていた問題を修正した。未設定またはAllow allの場合はAudit all (`RestrictSendingNTLMTraffic=1`)を設定し、既存のDeny all (`2`)や不明な値・型は維持する。拒否設定を明示的に監査へ変更するには`-OutgoingNtlmMode Audit`、ブロックを有効にするには`Deny`を指定する。書き込み前にポリシーを再確認し、変更後の値の検証、失敗の報告、確認できたポリシー状態と取得可能な最終適用RSoP情報の表示に対応した。 (#388) (@Shirofune-Security)
- `audit-settings`でホストの役割に適用されない監査ポリシーを`Not applicable`と表示し、カテゴリの有効・無効の集計から除外するようにした。NTLMポリシーの値は、DWORD型で保存されている場合にのみ有効な設定値として解釈・検証する。 (#392) (@Shirofune-Security)
- 設定時に外部コマンドの終了コードと変更後の設定値を確認し、処理の終了前にも再確認するようにした。書き込み失敗、設定の未反映、CAサービスの再起動失敗、最終確認時の設定の不一致を明示的に報告し、一律に成功とせず、0以外の終了コードを返すようにした。 (#392) (@Shirofune-Security)
- `configure`で全てのホストに`AuditNTLMInDomain=2`を設定していた問題を修正し、ドメインコントローラと確認できたホストにのみ`7` (Enable all)を設定するようにした。その他のホストや役割を判定できないホストでは、この設定を変更しない。ドメインNTLM監査設定を明示的に表示し、設定後の値の確認とレジストリエラーの報告にも対応した。 (#389) (@Shirofune-Security)
- ルールのフィルタ条件が全て適用されず最後の条件のみが適用されていたため、ルール数が正確ではなかった。 (#358) (@fukusuket)
- 依存するログが無効になっているルールも使用可能として報告されていた。 (#358) (@fukusuket)
- 複数のカテゴリに属するルールが重複してカウントされ、CSVファイルにも重複して出力されていた。 (#358) (@fukusuket)
- どのカテゴリにも一致しないルールがCSVファイルとカバレッジの母数から除外されていた。現在は`Uncategorized`として報告される。 (#358) (@fukusuket)
- 使用率のしきい値が文字列として比較されていたため、割合の表示色が正しくなかった。 (#358) (@fukusuket)
- 監査が有効であるにもかかわらず`Success and Failure`が赤色で表示されていた。 (#358) (@fukusuket)
- MITRE ATT&CK Navigatorのレイヤーに不正なテクニックIDが含まれ、またUTF-16で出力されるためATT&CK Navigatorで読み込めなかった。 (#358) (@fukusuket)
- WELAが配置されているディレクトリ以外から実行すると失敗していた。 (#358) (@fukusuket)
- `audit-filesize`で1つのログが存在しないだけでチェック全体が中断されていた。 (#358) (@fukusuket)
- PowerShellのログ設定を32bitのレジストリビューからしか読んでいなかったため、GPOで設定された端末が`Disabled`と報告されていた。 (#358) (@fukusuket)
- `auditpol`の出力のパースが失敗する場合があり、また管理者権限なしで`audit-settings`を実行すると誤った結果を報告していた。 (#358) (@fukusuket)
- `configure -Baseline ASD`が警告なくYamatoSecurityの設定を適用していた。 (#358) (@fukusuket)
- `update-rules`のダウンロードに失敗した場合、既存の設定ファイルが壊れる可能性があった。 (#358) (@fukusuket)
- `std`、`table`、`gui`の各出力形式でCSVの出力が一貫していなかった。 (#358) (@fukusuket)
- リリースとCSV作成のGitHub Actionsワークフローが失敗していた。 (#358) (@fukusuket)

**注意:** 上記の修正により、報告される使用率は2.1.0より低くなる(同一端末で23.38% -> 12.94%)。新しい値が正しい値であり、ログが無効なルールが使用可能としてカウントされなくなったことと、これまで除外されていたルールが母数に含まれるようになったことによるもの。

## 2.1.0 [2026/02/13] - Winter Release

**バグ修正:**

- 設定によりドメインコントローラのNetlogonが破損する可能性があった。 (#243) (@fukusuket) (この件を報告してくれた@feiglein74に感謝!)

## 2.0.0 [2025/11/16] - CODE BLUE リリース

**新機能:**

- プロファイルの plan/audit/configure に対象を限定した SACL の読み取り専用計画を追加しました。オブジェクト監査ポリシー、ユーザーハイブ・フォルダーリダイレクトの未確認箇所、WEF Run/RunOnce の監査エントリを表示し、`-SaclMode Skip` による省略も明示します。SACL の書き込みや未検証の検知率向上は行いません。 (issue #373) (@Shirofune-Security)


- MITRE ATT&CK Navigatorヒートマップに対応した。 (#11) (@fukusuket)
- Windows設定を様々なベースラインに構成するための`configure`コマンドを追加した。 (#12) (@fukusuket)
- Defender for Identityの必要なログに対応した。 (#114) (@fukusuket)

**バグ修正:**

- ルールカウントの一部が正確ではなかった。 (#99) (@fukusuket)
- タスクスケジューラのログ設定が正確に報告されていなかった。 (#100 (@fukusuket))

## 1.0.0 [2025/05/20] - AUSCERT/SINCON リリース

**新機能:**

- `audit-settings`: Windows Event Log audit policy settingsをチェックする
- `audit-filesize`: Windows Event Logファイルサイズをチェックする
- `update-rules`: WELAのSigmaルール設定ファイルを更新する
