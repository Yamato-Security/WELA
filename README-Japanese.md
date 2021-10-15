<div align="center">
 <p>

  ![WELA Logo](WELA-Logo.png)
  <h1>
   WELA (Windows Event Log Analyzer) ゑ羅（ウェラ）
  </h1>
 </p>
</div>

Yamato SecurityのWELA(Windows Event Log Analyzer)(ゑ羅(ウェラ))は、Windowsイベントログの様々な解析のためのマルチツールを目指しています。
現在、WELAの一番の機能は、迅速なフォレンジック調査とインシデントレスポンスを支援するために、分析しやすいログオンタイムラインを作成することです。
WELAのログオンタイムライン作成機能は、複数のログオンログエントリ(4624, 4634, 4647, 4672, 4776)の有用な情報のみを単一のイベントに集約し、ノイズの約90%を無視してデータ削減し、読みにくいデータ(16進数のステータスコードなど)を人間が読める形式に変換します。

Windows Powershell 5.1で動作確認済みですが、以前のバージョンでも動作する可能性があります。Powershell CoreにはWindowsイベントログを読み込む機能がないため、残念ながら対応していません。

## 機能

 - PowerShellで書かれているので、読みやすく、カスタマイズも簡単。
 - ファストフォレンジックのログオンタイムライン作成
   - 横展開の検知、システムの使用の確認、不審なログオン、脆弱なプロトコルの使用等々
   - ログオンイベントの90%以上のノイズリダクション
   - ログオン経過時間の計算
   - GUIによる解析
   - ログオンタイプのサマリ
 - ライブ調査とオフライン解析
 - 日本語対応
 - イベントIDの集計
 - Timeline Explorer等で解析するためのCSV出力

## 予定している機能

 - SIGMAルールの対応
 - カスタムな攻撃検知のルール
 - リモート解析
 - ログオン情報の集計

## 使い方

現在、Windows Powershell 5.1にしか対応していません。
ライブ調査を行う場合はローカル管理者権限が必用です。

    解析ソースを一つ指定して下さい：
        -LiveAnalysis : ホストOSのログでタイムラインを作成する
        -LogFile <ログファイルのパス> : オフラインの.evtxファイルでタイムラインを作成する

    解析タイプを一つ指定して下さい:
        -AnalyzeNTLM_UsageBasic : NTLM Operationalログを解析し、NTLM認証の使用を簡潔に出力する
        -AnalyzeNTLM_UsageDetailed : NTLM Operationalログを解析し、NTLM認証の使用を詳細に出力する
        -EventIDStatistics : イベントIDの集計情報を出力する
        -LogonTimeline : ユーザログオンの簡単なタイムラインを出力する

    解析オプション:
        -StartTimeline "<YYYY-MM-DD HH:MM:SS>" : タイムラインの始まりを指定する
        -EndTimeline "<YYYY-MM-DD HH:MM:SS>" : タイムラインの終わりを指定する

    -LogonTimelineの解析オプション:
        -IsDC : ドメインコントローラーのログの場合は指定して下さい

    出力方法（デフォルト：標準出力）:
        -SaveOutput <出力パス> : テキストファイルに出力する
        -OutputCSV : CSVファイルに出力する
        -OutputGUI : Out-GridView GUIに出力する

    出力オプション:
        -USDateFormat : 日付をMM-DD-YYYY形式で出力する (デフォルト： YYYY-MM-DD)
        -EuropeDateFormat : 日付をDD-MM-YYYY形式で出力する (デフォルト： YYYY-MM-DD)
        -UTC : 時間をUTC形式で出力する。（デフォルトはローカルタイムゾーン）
        -Japanese : 日本語で出力する

    -LogonTimelineの出力オプション:
        -HideTimezone :  タイムゾーンの表示をしない
        -ShowLogonID : ログオンIDを出力する

    その他:
        -ShowContributors : コントリビューターの一覧表示
        -QuietLogo : ロゴを表示させずに実行する

## 便利な機能

どのようなイベントがあるかを把握するためにまずイベントIDを集計する：

    ./WELA.ps1 -EventIDStatistics

オフライン解析でタイムラインを作成して、UTC時間でGUIで表示する：

    .\WELA.ps1 -LogFile .\Security.evtx -LogonTimeline -OutputGUI -UTC

## スクリーンショット

ログオンタイムラインのGUI:

![Logon Timeline GUI](/Screenshots/Screenshot-LogonTimelineGUI.png)

イベントID集計:

![Event ID Statistics](/Screenshots/Screenshot-EventIDStatistics.png)

ログオンタイプのサマリ:

![Logon Type Summary](/Screenshots/Screenshot-LogonTypeSummary.png)

## 関連するWindowsイベントログのスレットハンティングプロジェクト

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) Pythonで書かれた攻撃検知ツール。
- [Chainsaw](https://github.com/countercept/chainsaw) Rustで書かれたSIGMAベースの攻撃検知ツール。
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Powershellで書かれた攻撃検知ツール。
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) 攻撃の痕跡が入っているEVTXサンプルファイルのリポジトリ。
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) DeepBlueCLIをRustに書き換えたツール。
- [SIGMA](SIGMA: https://github.com/SigmaHQ/sigma) SIEM等のジェネリックな攻撃検知ルール。
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) evtxファイルをSecurity Onionにインポートするコマンド。
- [Zircolite](https://github.com/wagga40/Zircolite) Pythonで書かれたSIGMAベースの攻撃検知ツール。


## プロジェクトに貢献

コントリビューター大募集中！プルリクエストが一番ですが、新機能のリクエスト、バグのお知らせ等々も大歓迎！