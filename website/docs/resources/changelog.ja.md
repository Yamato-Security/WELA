# 変更履歴

!!! info "情報"
    このページはプロジェクトの [`CHANGELOG.md`](https://github.com/Yamato-Security/WELA/blob/main/CHANGELOG-Japanese.md) を反映したものです。ダウンロードは [リリースページ](https://github.com/Yamato-Security/WELA/releases) をご覧ください。

## 2.2.0 [2026/08/31] - Dev Release

**改善:**

- ベースライン定義を`WELA.ps1`から`config/baselines.json`に外部化し、ベースラインの追加・変更をJSONの編集のみで行えるようにした。 (#358) (@fukusuket)

**バグ修正:**

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
