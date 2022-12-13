<div align="center">
 <p>
    <img alt="WELA Logo" src="WELA-Logo.png" width="20%">
  <h1>
   WELA (Windows Event Log Analyzer) ゑ羅
  </h1>
   [<b>English</b>] | [<a href="README-Japanese.md">日本語</a>]

 </p>
</div>

---

[tag-1]: https://img.shields.io/github/stars/Yamato-Security/wela?style=plastic&label=GitHub%F0%9F%AA%9FStars
[tag-2]: https://img.shields.io/github/v/release/Yamato-Security/wela?display_name=tag&label=latest-version&style=plastic

![tag-1] ![tag-2]

Windows Event Log Analyzer) aims to be the Swiss Army knife for Windows event logs.
Currently, WELA's greatest functionality is creating an easy-to-analyze logon timeline in to order to aid in fast forensics and incident response.
WELA's logon timeline generator will consolodate only the useful information in multiple logon log entries (4624, 4634, 4647, 4672, 4776) into single events, perform data reduction by ignoring around 90% of the noise, and will convert any hard to read data (such as hex status codes) into human readable format.

Tested on Windows Powershell 5.1 but may work with previous versions. It will unfortunately NOT work with Powershell Core as there is no built-in functionality to read Windows event logs.

## Features

 - Written in PowerShell so is easy to read and customize.
 - Fast Forensics Logon Timeline Generator
   - Detect lateral movement, system usage, suspicious logons, vulnerable protocol usage, etc...
   - 90%+ noise reduction for logon events
   - Calculate Logon Elapsed Time
   - GUI analysis
   - Logon Type Summary
 - Live Analysis and Offline Analysis
 - Japanese support
 - Event ID Statistics
 - Output to CSV to analyze in Timeline Explorer, etc...
 - Analyze NTLM usage before disabling NTLM
 - Sigma rules
 - Custom attack detection rules
 - Remote analysis
 - Logon Statistics

## Usage

At the moment, please use a Windows Powershell 5.1.
You will need local Administrator access for live analysis.

```powershell
    Analysis Source (Specify one):
        -LiveAnalysis : Creates a timeline based on the live host's log
        -LogFile <path-to-logfile> : Creates a timelime from an offline .evtx file
        -LogDirectory <path-to-logfiles> (Warning: not fully implemented.) : Analyze offline .evtx files
        -RemoteLiveAnalysis : Creates a timeline based on the remote host's log

    Analysis Type (Specify one):
        -AnalyzeNTLM_UsageBasic : Returns basic NTLM usage based on the NTLM Operational log
        -AnalyzeNTLM_UsageDetailed : Returns detailed NTLM usage based on the NTLM Operational log
        -EventID_Statistics : Output event ID statistics
        -LogonTimeline : Output a condensed timeline of user logons based on the Security log
        -SecurityAuthenticationSummary : Output a summary of authentication events for each logon type based on the Security log

    Analysis Options:
        -StartTimeline "<YYYY-MM-DD HH:MM:SS>" : Specify the start of the timeline
        -EndTimeline "<YYYY-MM-DD HH:MM:SS>" : Specify the end of the timeline

    -LogonTimeline Analysis Options:
        -IsDC : Specify if the logs are from a DC

    Output Types (Default: Standard Output):
        -SaveOutput <outputfile-path> : Output results to a text file
        -OutputCSV : Outputs to CSV
        -OutputGUI : Outputs to the Out-GridView GUI

    General Output Options:
        -USDateFormat : Output the dates in MM-DD-YYYY format (Default: YYYY-MM-DD)
        -EuropeDateFormat : Output the dates in DD-MM-YYYY format (Default: YYYY-MM-DD)
        -UTC : Output in UTC time (default is the local timezone)
        -Japanese : Output in Japanese

    -LogonTimeline Output Options:
        -HideTimezone : Hides the timezone
        -ShowLogonID : Show logon IDs

    Other:
        -ShowContributors : Show the contributors
        -QuietLogo : Do not display the WELA logo
```

## Useful Options

### Show event ID statistics to get a grasp of what kind of events there are:
```powershell
./WELA.ps1 -LogFile .\Security.evtx -EventID_Statistics
```

### Create a timeline via offline analysis outputted to a GUI in UTC time:
```powershell
.\WELA.ps1 -LogFile .\Security.evtx -SecurityLogonTimeline -OutputGUI -UTC
```

### Analyze NTLM Operational logs for NTLM usage before disabling it:
```powershell
.\WELA.ps1 -LogFile .\DC1-NTLM-Operational.evtx -AnalyzeNTLM_UsageBasic 
```

### Security logon statistics on a live machine:
```powershell
.\WELA.ps1 -LiveAnalysis -SecurityAuthenticationSummary
```

## Screenshots

### Logon Timeline GUI:

![Logon Timeline GUI](/Screenshots/Screenshot-LogonTimelineGUI.png)

### Human Readable Timeline:

![Logon Timeline GUI](/Screenshots/Screenshot-HumanReadableTimeline.png)

### Logon Type Statistics:

![Logon Statistics](/Screenshots/Screenshot-LogonStatistics.png)

### Event ID Statistics:

![Event ID Statistics](/Screenshots/Screenshot-EventIDStatistics.png)

### Logon Type Summary:

![Logon Type Summary](/Screenshots/Screenshot-LogonTypeSummary.png)

### NTLM Authentication Analysis:

![Logon Type Summary](/Screenshots/Screenshot-NTLM-Statistics-EN.png)

## Related Windows Event Log Threat Hunting Projects

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) - Sigma-based attack detection tool written in Rust.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Attack detection tool written in Powershell.
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - EVTX Attack sample event log files.
- [Hayabusa](https://github.com/Yamato-Security/hayabusa/blob/main/README-English.md) - Sigma-based attack detection and fast forensics timeline generator by [Yamato Security](https://github.com/Yamato-Security/).
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) Rust port of DeepBlueCLI.
- [Sigma](https://github.com/SigmaHQ/sigma) - generic SIEM rules.
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Import evtx files into Security Onion.
- [Zircolite](https://github.com/wagga40/Zircolite) - Sigma-based attack detection tool written in Python.

## Contribution

We would love any form of contributing. Pull requests are the best but feature requests, notifying us of bugs, etc... are also very welcome.