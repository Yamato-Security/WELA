<#
    .SYNOPSIS
    WELA (Windows Event Log Analyzer) is the Swiss Army knife for Windows event logs fast forensics.
    WELA (Windows Event Log Analyzer)はWindowsイベントログのファストフォレンジック調査のための多目的な解析ツールです。

    .DESCRIPTION
    Yamato Security's WELA(Windows Event Log Analyzer) is the Swiss Army knife for Windows event logs fast forensics.
    WELA's main goal is to create easy-to-analyze and as noise-free as possible event timelines and statistics to order to aid in quicker and higher quality forensic analysis.

    Currently it only supports analyzing the security event log but will soon support other logs as well as detect attacks with custom rules as well as SIGMA rules.
    By combining multiple log entries into single events of interest and ignoring data not relevant to forensic analysis, WELA usually performs data reducution 
    of noise of around 90%. WELA also will convert any hard to read data (such as hex status codes) into human readable format.

    Tested on Windows Powershell 5.1 with future plans to support Powershell Core on Windows, Linux and MacOS.

    大和セキュリティのWELA (Windows Event Log Analyzer)はWindowsイベントログのファストフォレンジック調査のための多目的な解析ツールです。
    WELAの主なゴールはフォレンジック調査をより迅速、より高い精度でできるようになるべくノイズが少ない解析しやすいフォレンジックタイムラインを作ることです。

    現在は主に「セキュリティ」ログを解析していますが、その他のログ、独自ルールによる攻撃検知、SIGMAルールによる攻撃検知等々に対応する予定です。
    WELAは複数のログから情報を簡潔にまとめて、フォレンジック調査に役立つデータのみを抽出し、16進数のステータスコードなどユーザが理解しやすい形に変換して、
    フォレンジック調査に役立つデータのみを抽出することができます。

    Windows Powershell 5.1で検証済。Windows、Linux、MacOSでのPowershell Coreに対応する予定です。
    
    .Example
    Get the help menu(ヘルプメニューの表示):
    .\WELA.ps1

    Output Security Log Event ID Statistics (イベントIDの集計):
    .\WELA.ps1 -SecurityEventID_Statistics

    Live Analysis Timeline Generation (ライブ調査のタイムライン作成):
    .\WELA.ps1 -SecurityLogonTimeline -LiveAnalysis 

    Offline Analysis Timeline Generation (オフライン調査のタイムライン作成):
    .\WELA.ps1 -SecurityLogonTimeline -LogFile .\Cobalt-Strike-Security.evtx 
    
    Analyze with a GUI(GUIでの解析):
    -OutputGUI

    日本語出力：
    -Japanese

    Save Output(結果の保存):
    -SaveOutput file.txt

    Display in UTC time (by default, it displays in local time) (UTC時間での表示。デフォルトはローカル時間)：
    -UTC

    Security Logon Timeline Option: Show Logon IDs(Default: false)(ログオンIDの表示):
    -ShowLogonID

    .LINK
    https://github.com/Yamato-Security/WELA
#>

# Tool: Windows Event Log Analyzer (WELA)
# Author: Zach Mathis, Yamatosecurity founder
# Other Core Developers: DustInDark, Chihiro (Ogino)
# Twitter: @yamatosecurity
# https://yamatosecurity.connpass.com/
#
# ツール名: Windows Event Log Analyzer (WELA・ゑ羅・ウェラ)
# 作者: 田中ザック
# その他のコア開発者： DustInDark, Chihiro (Ogino)
# Twitter: @yamatosecurity
# https://yamatosecurity.connpass.com/
#
# 
# Inspired by Eric Conrad's DeepBlueCLI (https://github.com/sans-blue-team/DeepBlueCLI)
# Much help and inspiration from the Windows Event Log Analysis Cheatsheets by Steve Anson (https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf)
# and event log info from www.ultimatewindowssecurity.com.
# Many thanks to SIGMA: https://github.com/SigmaHQ/sigma
# as well as sbousseaden for providing sample attack event logs at https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
#
# Eric Conrad氏のDeepBlueCLIからインスピレーションを受けました。 (https://github.com/sans-blue-team/DeepBlueCLI)
# Steve Anson氏のWindows Event Log Analysis Cheatsheet (https://www.forwarddefense.com/en/article/references-pdf)と
# www.ultimatewindowssecurity.comのイベントログ情報も参考にしています。
# 他に参考にしているプロジェクト：
#   SIGMA: https://github.com/SigmaHQ/sigma
#   sbousseaden氏の攻撃のサンプルイベントログ： https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

param (
    [switch]$Japanese,
    [switch]$English,
    [switch]$USDateFormat,
    [switch]$EuropeDateFormat,
    [string]$SaveOutput = "",
    [string]$StartTimeline = "",
    [string]$EndTimeline = "",
    [switch]$IsDC,
    [switch]$ShowLogonID,
    [switch]$LiveAnalysis,
    [switch]$RemoteLiveAnalysis,
    [string]$LogFile = "",
    [string]$LogDirectory = "",
    [switch]$ShowContributors,
    [switch]$SecurityEventID_Statistics,
    [switch]$SecurityLogonTimeline,
    [switch]$EasyToReadSecurityLogonTimeline,
    [switch]$AccountInformation,
    [switch]$OutputGUI,
    [switch]$OutputCSV,
    [switch]$UTC,
    [switch]$HideTimezone,
    [switch]$QuietLogo,
    [string]$UseDetectRules = "0",
    [switch]$AnalyzeNTLM_UsageBasic,
    [switch]$AnalyzeNTLM_UsageDetailed
)

$ruleStack = @{};
#Global variables
$YEAVersion = "1.0"
$AnalyzersPath = $PSScriptRoot + "\Analyzers\"
$HostLanguage = Get-WinSystemLocale | Select-Object Name # en-US, ja-JP, etc..
$ProgramStartTime = Get-Date
$DisplayTimezone = !($HideTimezone);

#Startup stuff:
if (!$QuietLogo) {
    Invoke-Expression './Config/splashlogos.ps1'
}

$ProgramStartTime = Get-Date

Import-Module './Config/util.ps1' -Force ;

$exectionpolicy = Get-ExecutionPolicy

# Read Rules
switch ($UseDetectRules.toupper()) {
    "0" { break; }
    "1" { 
        Get-ChildItem -Path './Rules/WELA-Rules' -Recurse -Filter *.ps1 | Foreach-Object { Import-Module $_.FullName -Force; . Add-Rule }
        break;
    }
    "2" {
        Write-Host $Confirm_DefConfirm_ExecutionPolicy_Bypassed -ForegroundColor Black -BackgroundColor Yellow
        if ($exectionpolicy.ToString().ToUpper() -ne "BYPASS") {
            Write-Host $Error_ExecutionPolicy_Bypassed -ForegroundColor White -BackgroundColor Red
        }
        Get-ChildItem -Path './Rules/SIGMA' -Recurse -Filter *.ps1 | Foreach-Object { Import-Module $_.FullName -Force; . Add-Rule }
        break;
    }
    "ALL" {
        Get-ChildItem -Path './Rules' -Recurse -Filter *.ps1 | Foreach-Object { Import-Module $_.FullName -Force; . Add-Rule }
        break;
    }
    Default {}
}
#Functions:

#Set the language: English or Japanese
if ( $HostLanguage.Name -eq "ja-JP" -and $English -eq $true ) {
    Import-Module './Config/Language/en.ps1' -Force;
}
elseif ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
    Import-Module './Config/Language/ja.ps1' -Force;
}
else {
    Import-Module './Config/Language/en.ps1' -Force;
}

#Set the date format
$DateFormat = "yyyy-MM-dd HH:mm:ss.ff"

if ( $USDateFormat -eq $true ) {
    $DateFormat = "MM/dd/yyyy HH:mm:ss.ff"
} 

if ( $EuropeDateFormat -eq $true ) {
    $DateFormat = "dd.MM.yyyy HH:mm:ss.ff"
} 

#Set timezone
$Timezone = Get-TimeZone
$TimezoneName = $Timezone.DisplayName #例：(UTC+09:00 Osaka, Sapporo, Tokyo)
$StartParen = $TimezoneName.IndexOf('(') #get position of (
$EndParen = $TimezoneName.IndexOf(')') #position of )
$UTCOffset = $TimezoneName.SubString( $StartParen + 1 , $EndParen - $StartParen - 1 ) # UTC+09:00
if ( $UTC -eq $true ) {
    $UTCOffset = "UTC"
}

#Check $StartTimeline and $EndTimeline
if ( $StartTimeline -ne "" ) {
    $StartTimeline = Check-DateString -DateString $StartTimeline -DateFormat $DateFormat
    if ( $StartTimeline -eq "" ) {
        Write-Host
        Write-Host $Error_Incorrect_StartTimeline -ForegroundColor White -BackgroundColor Red # Error: Failed to parse Starttimeline. Please check the format of the input value.
        Write-Host 
        exit
    }
}

if ( $EndTimeline -ne "" ) {
    $EndTimeline = Check-DateString -DateString $EndTimeline -DateFormat $DateFormat
    if ( $EndTimeline -eq "" ) {
        Write-Host
        Write-Host $Error_Incorrect_EndTimeline -ForegroundColor White -BackgroundColor Red # Error: Failed to parse Endtimeline. Please check the format of the input value.
        Write-Host 
        exit
    }
}

#Functions:
function Show-Contributors {
    Write-Host 
    Write-Host $Show_Contributors1 -ForegroundColor Red 
    Write-Host $Show_Contributors2 -ForegroundColor Cyan
    Write-Host
}


function Check-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function Perform-LiveAnalysisChecks {
    if ( $IsWindows -eq $true -or $env:OS -eq "Windows_NT" ) {
        
        #Check if running as an admin
        $isAdmin = Check-Administrator

        if ( $isAdmin -eq $false ) {
            Write-Host
            Write-Host $Error_NeedAdministratorPriv -ForegroundColor White -BackgroundColor Red
            Write-Host
            Exit
        }
    
    }
    else {
        #Trying to run live analysis on Mac or Linux
        Write-Host
        Write-Host $Error_NotSupport_LiveAnalysys -ForegroundColor White -BackgroundColor Red
        Write-Host
        Exit
    }
}



#Main

# -ShowContributors
if ( $ShowContributors -eq $true ) {
    Show-Contributors
    exit
}


if ( ($LiveAnalysis -eq $true -or $RemoteLiveAnalysis -eq $true ) -and $IsDC -eq $true ) {
    Write-Host
    Write-Host $Warn_DC_LiveAnalysis -ForegroundColor Black -BackgroundColor Yellow #Warning: You probably should not be doing live analysis on a Domain Controller. Please copy log files offline for analysis.
    Write-Host 
    exit
}

#Error: You cannot specify -LiveAnalysis and -LogFile (or -LogDirectory) at the same time
if ( $LiveAnalysis -eq $true -and ($LogFile -ne "" -or $LogDirectory -ne "")) {
    Write-Host
    Write-Host $Error_InCompatible_LiveAnalysisAndLogFile -ForegroundColor White -BackgroundColor Red  # Error: You cannot specify -LiveAnalysis and -LogFile (or -LogDirectory) at the same time
    Write-Host 
    exit
}

# Show-Helpは各言語のModuleに移動したためShow-Help関数は既に指定済みの言語の内容となっているため言語設定等の参照は行わない
if ( $LiveAnalysis -eq $false -and $RemoteLiveAnalysis -eq $false -and $LogFile -eq "" -and $SecurityEventID_Statistics -eq $false -and $SecurityLogonTimeline -eq $false -and $AccountInformation -eq $false -and $AnalyzeNTLM_UsageBasic -eq $false -and $AnalyzeNTLM_UsageDetailed -eq $false) {

    Show-Help
    exit

}

#No analysis source was specified
if (    $SecurityEventID_Statistics -eq $true -or 
    $SecurityLogonTimeline -eq $true -or 
    $AnalyzeNTLM_UsageBasic -eq $true -or 
    $AnalyzeNTLM_UsageDetailed -eq $true ) {

    if ( $LiveAnalysis -ne $true -and $LogFile -eq "" -and $LogDirectory -eq "") {

        Write-Host
        Write-Host $Error_InCompatible_NoLiveAnalysisOrLogFileSpecified -ForegroundColor White -BackgroundColor Red # Error: You need to specify -LiveAnalysis or -LogFile
        Write-Host 
        exit

    }

}

# -LogFile
$evtxFiles = [System.Collections.ArrayList] @()
if ($LogFile -ne "") {
    [void]$evtxFiles.Add($LogFile)
}

if ( $LiveAnalysis -eq $true -or $RemoteLiveAnalysis -eq $true ) {

    Perform-LiveAnalysisChecks
    if ($AnalyzeNTLM -eq $true) {

        $evtxFiles = @(
            "C:\Windows\System32\Winevt\Logs\Microsoft-Windows-NTLM%4Operational.evtx"
        )
    }
    elseif ($SecurityLogonTimeline -eq $true -or $SecurityEventID_Statistics -eq $true) {
        $evtxFiles = @(
            "C:\Windows\System32\winevt\Logs\Security.evtx"
        )
    } 
    else {
        $evtxFiles = @(
            "C:\Windows\System32\winevt\Logs\Security.evtx",
            "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
        )
    }
    
    if ( $RemoteLiveAnalysis -eq $true ) {
        $RemoteComputerInfo = Get-RemoteComputerInfo #Get credential and computername
    }
        
}
# -LogDirectory
elseif ( $LogDirectory -ne "" ) {

    if ($LogFile -ne "") {
        Write-Host
        Write-Host $Error_InCompatible_LogDirAndFile -ForegroundColor White -BackgroundColor Red
        Write-Host 
        exit
    }
    
    Get-ChildItem -Filter *.evtx -Path $LogDirectory | ForEach-Object { [void]$evtxFiles.Add($_.FullName) }
}

# Run analysis
foreach ( $LogFile in $evtxFiles ) {

    if ( $SecurityEventID_Statistics -eq $true ) {

        .  ($AnalyzersPath + "Security-EventID_Statistics.ps1")
        Create-SecurityEventIDStatistics -filePath $LogFile
        
    }
    
    if ( $SecurityLogonTimeline -eq $true ) {
        .  ($AnalyzersPath + "Security-LogonTimeline.ps1")
        Create-SecurityLogonTimeline $UTCOffset -filePath $LogFile
    
    }

    if ( $EasyToReadSecurityLogonTimeline -eq $true ) {
        .  ($AnalyzersPath + "Security-LogonTimeline.ps1")
        Create-EasyToReadSecurityLogonTimeline $UTCOffset -filePath $LogFile
    
    }

    if ( $AnalyzeNTLM_UsageBasic -eq $true) {

        .  ($AnalyzersPath + "NTLM-Operational-Usage.ps1")
        Analyze-NTLMOperationalBasic

    }

    if ( $AnalyzeNTLM_UsageDetailed -eq $true) {

        .  ($AnalyzersPath + "NTLM-Operational-Usage.ps1")
        Analyze-NTLMOperationalDetailed
        
    }
}

$progcnt = 0;
$maxprogcnt = $evtxFiles.Count * $ruleStack.Count
$interval = $maxprogcnt * 0.1
if ($ruleStack.Count -ne 0) {
    foreach ($LogFile in $evtxFiles) {
        $WineventFilter = @{}
        $WineventFilter.Add( "Path", $LogFile ) 
        # write-host "execute rule to $LogFile"
        $logs = Get-WinEventWithFilter -WinEventFilter $WineventFilter -RemoteComputerInfo $RemoteComputerInfo
        foreach ($rule in $ruleStack.keys) {
            #write-host "execute rule:$rule"
            Invoke-Command -scriptblock $ruleStack[$rule] -ArgumentList @($logs)
        }
        $progcnt += 1;
        if ($progcnt % $interval -eq 0) {
            Write-Host "Check Detect Rule... Checked File($progcnt of $maxprogcnt)" -ForegroundColor Black -BackgroundColor Green
        }
    }
}

Remove-Variable ruleStack
Set-ExecutionPolicy $exectionpolicy -scope Process