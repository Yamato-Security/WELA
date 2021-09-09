<div align="center">
 <p>
  <h1>
   WELA (Windows Event Log Analyzer) ゑ羅 (ウェラ)
  </h1>
 </p>
</div>

 Yamato Security's WELA(Windows Event Log Analyzer) is a fast forensics timeline generator for Windows event logs.
WELA's main goal is to create easy-to-analyze and as noise-free as possible event timelines to order to aid in quicker and higher quality forensic analysis.
Currently it only supports analyzing the security event log but will soon support other logs as well as detect attacks with custom rules as well as SIGMA rules.
By combining multiple log entries into single events of interest and ignoring data not relevant to forensic analysis, WELA usually performs data reducution 
of noise of around 90%. WELA also will convert any hard to read data (such as hex status codes) into human readable format.

Tested on Windows Powershell 5.1 with future plans to support Powershell Core on Windows, Linux and MacOS.

大和セキュリティのWELA (Windows Event Log Analyzer)はWindowsイベントログのファストフォレンジック調査用のタイムライン作成ツールです。
WELAの主なゴールはフォレンジック調査をより迅速、より高い精度でできるようになるべくノイズが少ない解析しやすいフォレンジックタイムラインを作ることです。

現在は主に「セキュリティ」ログを解析していますが、その他のログ、独自ルールによる攻撃検知、SIGMAルールによる攻撃検知等々に対応する予定です。
WELAは複数のログから情報を簡潔にまとめて、フォレンジック調査に役立つデータのみを抽出し、16進数のステータスコードなどユーザが理解しやすい形に変換して、
フォレンジック調査に役立つデータのみを抽出することができます。

Windows Powershell 5.1で検証済。Windows、Linux、MacOSでのPowershell Coreに対応する予定です。

## Features

 - Written in PowerShell so is easy to read and customize.
 - Live Analysis and Offline Analysis
 - Detecting lateral movement, system usage, attacks, etc...
 - 90%+ noise reduction of logon events
 - Japanese support
 - GUI analysis

## Planned Features

 - SIGMA rule support
 - Custom attack detection rules
 - Remote analysis

## Usage

At the moment, please use a Windows Powershell 5.1.
You will need local Administrator access for live analysis.


    Analysis Source (Specify one):
        -LiveAnalysis : Creates a timeline based on the live host's log
        -LogFile <path-to-logfile> : Creates a timelime from an offline .evtx file

    Analysis Type (Specify one):
        -EventIDStatistics : Output event ID statistics
        -LogonTimeline : Output a simple timeline of user logons

    Output Types (Default: Standard Output):
        -SaveOutput <outputfile-path> : Output results to a text file
        -OutputCSV : Outputs to CSV (Default: $false)
        -OutputGUI : Outputs to the Out-GridView GUI (Default: $false)

    Analysis Options:
        -StartTimeline "<YYYY-MM-DD HH:MM:SS>" : Specify the start of the timeline
        -EndTimeline "<YYYY-MM-DD HH:MM:SS>" : Specify the end of the timeline
        -IsDC $true : Specify if the logs are from a DC (Default: $false)

    Output Options:
        -USDateFormat : Output the dates in MM-DD-YYYY format (Default: YYYY-MM-DD)
        -EuropeDateFormat : Output the dates in DD-MM-YYYY format (Default: YYYY-MM-DD)
        -UTC : Output in UTC time (Default: $false)
        -HideDisplayTimezone : Hide Displays the timezone used
        -ShowLogonID : Specify if you want to see Logon IDs (Default: $false)
        -Japanese : Output in Japanese

    Other:
        -ShowContributors : Show the contributors

## 使い方

現在、Windows Powershell 5.1にしか対応していません。
ライブ調査を行う場合はローカル管理者権限が必用です。

    解析ソースを一つ指定して下さい：
        -LiveAnalysis : ホストOSのログでタイムラインを作成する
        -LogFile <path-to-logfile> : オフラインの.evtxファイルでタイムラインを作成する

    解析タイプを一つ指定して下さい:
        -EventIDStatistics : イベントIDの集計情報を出力する
        -LogonTimeline : ユーザログオンの簡単なタイムラインを出力する

    出力方法（デフォルト：標準出力）:
        -SaveOutput <出力パス> : テキストファイルに出力する
        -OutputGUI : Out-GridView GUIに出力する (デフォルト：$false)
        -OutputCSV : CSVファイルに出力する (デフォルト：$false)

    解析オプション:
        -StartTimeline "<YYYY-MM-DD HH:MM:SS>" : タイムラインの始まりを指定する
        -EndTimeline "<YYYY-MM-DD HH:MM:SS>" : タイムラインの終わりを指定する
        -IsDC : ドメインコントローラーのログの場合は指定して下さい

    出力オプション:
        -USDateFormat : 日付をMM-DD-YYYY形式で出力する (デフォルト：YYYY-MM-DD)
        -EuropeDateFormat $true : 日付をDD-MM-YYYY形式で出力する (デフォルト：YYYY-MM-DD)
        -UTC : 時間をUTC形式で出力する
        -HideDisplayTimezone :  タイムゾーンの表示をしない
        -ShowLogonID : ログオンIDを出力する (デフォルト：$false)
        -Japanese $true : 日本語で出力する

    その他:
        -ShowContributors $true : コントリビューターの一覧表示

## Useful Options

Show event ID statistics to get a grasph of what kind of events there are:

    .\WELA.ps1 -EventIDStatistics

Create a timeline via offline analysis outputted to a GUI in UTC time:

    .\WELA.ps1 -LogFile .\Security.evtx -LogonTimeline -OutputGUI -UTC

## 便利なオプション

どんなイベントがあるのかを把握するためにイベントIDを集計する：

    ./WELA.ps1 -EventIDStatistics

オフライン解析でタイムラインを作成して、UTC時間でGUIで表示する：

    .\WELA.ps1 -LogFile .\Security.evtx -LogonTimeline -OutputGUI -UTC

## Screenshots (スクリーンショット)

Event ID Statistics (イベントID集計):

![Alt text](/Screenshots/Screenshot-EventIDStatistics.png "Event ID Statistics")

Logon Type Summary (ログオンタイプのサマリー):

![Alt text](/Screenshots/Screenshot-LogonTypeSummary.png "Logon Type Summary")

Logon Timeline GUI (ログオンタイムラインのGUI):

![Alt text](/Screenshots/Screenshot-LogonTimelineGUI.png "Logon Timeline GUI")

## Related Windows Event Log Threat Hunting Projects

- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Attack detection tool written in Powershell.
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) Rust port of DeepBlueCLI.
- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) Attack detection tool written in Python.
- [Zircolite](https://github.com/wagga40/Zircolite) SIGMA based attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) SIGMA based attack detection tool written in Rust.

## Contributing

We would love any form of contributing. Pull requests are the best but feature requests, notifying us of bugs, etc... is also very welcome.
コントリビューター大募集中！