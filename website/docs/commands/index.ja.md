# コマンド一覧

WELA 3.0 では以下のコマンドを利用できます。各コマンドのオプションと安全上の制約は
`./WELA.ps1 <command> -Help` で確認してください。設定コマンドではヘルプに記載された
オプションだけを使用でき、別のコマンド用のオプションは拒否されます。

## プロファイル、評価、設定

| コマンド | 用途 |
| --- | --- |
| `profiles` | 組み込みまたは検証済みカスタム詳細監査プロファイルを一覧表示する。 |
| `plan` | 選択した詳細監査プロファイルのオフライン計画を作成する。 |
| `audit` | 選択した詳細監査プロファイルと実際のポリシーを比較する。 |
| `audit-settings` | 従来のベースラインまたはバージョン付きプロファイルで監査準備状況を評価する。 |
| `eventlog-profiles` | イベントログのサイズ／保存方式プロファイルを一覧表示する。 |
| `audit-filesize` | 実際のイベントログサイズと保存方式を読み取る。 |
| `configure-eventlogs` | レビュー済みのイベントログサイズ／保存方式プロファイルを適用する。 |
| `configure` | ネイティブログ制御または選択した詳細監査プロファイルを設定する。 |
| `configure-sacl` | 従来の対象限定ファイル／レジストリ監査 SACL を追加する。 |
| `audit-integrity` | 監査権限と監査失敗ポリシーを評価・計画・設定する。 |
| `audit-notifications` | OneSettings と Security ログ警告を評価または設定する。 |
| `retention-health` | ローカル保存、アーカイブ、転送の状態を上限付きで評価する。 |
| `event-measurement` | 既存チャネルの配信レートを計画または上限付きで測定する。 |
| `rule-eligibility` | 証拠を考慮した Sigma ルール利用可能性を計算する。 |
| `score` | 設定準拠と証拠付き準備状況を分けて採点する。 |
| `control-applicability` | 機能、役割、ビルド、エディションへの適用可否を評価する。 |
| `default-evidence` | Windows 既定値の正確な環境証拠を取得または比較する。 |

## ネイティブログ／監査制御

| コマンド | 用途 |
| --- | --- |
| `dns-analytical` | DNS Server 分析チャネルのライフサイクルを評価または設定する。 |
| `targeted-sacl` | 選択した既存ローカル対象の SACL を評価・計画・設定する。 |
| `adcs-auditing` | 明示的な再起動同意付きでローカル AD CS 監査を評価または設定する。 |
| `ldap-diagnostics` | 役割に応じた LDAP 1644 診断を評価または設定する。 |
| `provider-packs` | 任意のネイティブプロバイダーパックを一覧・評価・計画・設定する。 |
| `channel-read` | 選択したチャネルへの現在のトークンの読み取り権限を確認する。 |
| `channel-settings` | 選択したネイティブチャネル設定と読み取り権限を評価または設定する。 |
| `wmi-auditing` | 選択した WMI 名前空間 SACL を一覧・評価・計画・設定する。 |
| `firewall-logging` | Windows Firewall のネイティブテキストログを評価または設定する。 |
| `smb-runtime` | 選択した SMB 実行時監査スイッチを計画または明示的に有効化する。 |
| `smb-auditing` | バージョン対応の SMB 監査ポリシーを評価または設定する。 |
| `process-commandline` | Security 4688 のコマンドライン記録を評価または設定する。 |
| `powershell-logging` | 選択した Windows PowerShell イベントポリシーを評価または設定する。 |
| `powershell-transcription` | Windows PowerShell トランスクリプトを評価または設定する。 |
| `ntlm-auditing` | 受信およびドメイン NTLM 監査を評価または設定する。 |
| `outgoing-ntlm` | 送信 NTLM 監査を独立して評価または設定する。 |
| `ad-object-sacl` | 選択した AD／AD CS オブジェクト SACL を評価または設定する。 |
| `applocker-readiness` | AppLocker の準備状況を評価し、保護された監査専用ポリシーを取り込む。 |

共通するポリシーマスクと証拠の制限は
[ネイティブ監査制御と前提条件](native-audit-controls.md)を参照してください。

## Windows Event Forwarding と収集

| コマンド | 用途 |
| --- | --- |
| `wef-source` | ドメイン／Kerberos の WEF 送信元設定を評価・計画・設定する。 |
| `wef-query` | 選択した送信元 QueryList をローカルで実行する。 |
| `wef-arrival` | ローカル収集サーバーで正確なプローブイベント到着を確認する。 |
| `wec-collector` | レビュー済み収集サブスクリプションを評価・計画・作成する。 |
| `wec-runtime` | サブスクリプションの実行状態を上限付きで読み取る。 |
| `wec-listener` | HTTP 5985 収集リスナーを計画または作成する。 |
| `wec-ingress` | 範囲を限定した収集ファイアウォール規則を計画または作成する。 |
| `wec-authorization` | 1つのサブスクリプションの送信元 SID 認可をレビューまたは適用する。 |
| `wec-state` | 1つのサブスクリプションの有効／無効状態をレビューまたは適用する。 |
| `wec-update` | 1つのサブスクリプションのクエリと説明の更新をレビューまたは適用する。 |

## 証拠プローブと検証

| コマンド | 用途 |
| --- | --- |
| `registry-probe` | 所有する一時値のレジストリイベントを生成して照合する。 |
| `file-access-probe` | 監査対象ファイルの上限付き読み取りイベントを生成して照合する。 |
| `dns-client-probe` | 固定 DNS クライアント検索を生成して照合する。 |
| `capi2-probe` | オフライン CAPI2 チェーンイベントを生成して照合する。 |
| `failed-logon-probe` | 固定ローカルログオン失敗を生成して照合する。 |
| `wmi-probe` | 固定ローカル WMI 読み取りを生成して照合する。 |
| `applocker-script-probe` | 固定 AppLocker スクリプト判定イベントを収集する。 |
| `applocker-probe` | 固定 AppLocker 実行ファイル判定イベントを収集する。 |
| `transcript-probe` | Windows PowerShell 5.1 の自動トランスクリプトを確認する。 |
| `native-validation` | ポリシーを変更せず固定 Security 4688 プローブを収集する。 |

## レビュー付き復旧

| コマンド | 用途 |
| --- | --- |
| `registry-sacl-recovery` | 追加が証明されたレジストリ監査 ACE 1件の削除をレビューする。 |
| `file-sacl-recovery` | 追加が証明されたファイル監査 ACE 1件の削除をレビューする。 |
| `wmi-sacl-recovery` | 追加が証明された親 WMI 監査 ACE 1件の削除をレビューする。 |
| `transcription-recovery` | 1件のトランスクリプト設定の復元をレビューする。 |
| `audit-recovery` | 対応する監査／ログ制御の復元をレビューする。 |
| `channel-recovery` | 1件の channel-settings 操作の復元をレビューする。 |
| `eventlog-recovery` | 1件のイベントログサイズ／方式操作の復元をレビューする。 |
| `firewall-recovery` | 1件のファイアウォールテキストログ操作の復元をレビューする。 |
| `evtx-recovery` | 既存 EVTX から復旧可能なイベントを出力または検証する。 |
| `adcs-resume` | 保留中の AD CS 監査再起動をレビューして再開する。 |

## 配備とエクスポート

| コマンド | 用途 |
| --- | --- |
| `gpo-create` | レビュー済みの正規バックアップから無効・未リンクの新規 GPO を作成する。 |
| `gpo-package` | オフライン GPO 監査コンポーネントを計画・出力・検証する。 |
| `intune-export` | オフライン Intune 監査ポリシー成果物を出力して検証する。 |

## 保守とヘルプ

| コマンド | 用途 |
| --- | --- |
| `update-rules` | WELA の検知ルール設定ファイルを更新する。 |
| `version` | WELA のバージョンとリリース状態を表示する。 |
| `help` | 公開 CLI の例とコマンドヘルプを表示する。 |

実装、検証、復旧に関する詳細ガイドはリポジトリの
[`docs/` ディレクトリ](https://github.com/Yamato-Security/WELA/tree/dev/docs)で管理され、
リリースパッケージにも含まれます。
