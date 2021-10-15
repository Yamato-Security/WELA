<div align="center">
 <p>

  ![WELA Logo](WELA-Logo.png)
  <h1>
   WELA (Windows Event Log Analyzer) ゑ羅
  </h1>
 </p>
</div>

Yamato Security's WELA(Windows Event Log Analyzer) aims to be the Swiss Army knife for Windows event logs.
Currently, WELA's greatest functionality is creating an easy-to-analyze logon timeline in to order to aid in fast forensics and incident response.
WELA's logon timeline generator will consolodate only the useful information in multiple logon log entries (4624, 4634, 4647, 4672, 4776) into single events, perform data reduction by ignoring around 90% of the noise, and will convert any hard to read data (such as hex status codes) into human readable format.

Tested on Windows Powershell 5.1 but may work with previous versions. It will unfortunately NOT work with Powershell Core as there is no built-in functionality to read Windows event logs.

## Features

 - Written in PowerShell so is easy to read and customize.
 - Fast Forenscis Logon Timeline Generator
   - Detect lateral movement, system usage, suspicious logons, vulnerable protocol usage, etc...
   - 90%+ noise reduction for logon events
   - Calculate Logon Elapsed Time
   - GUI analysis
   - Logon Type Summary
 - Live Analysis and Offline Analysis
 - Japanese support
 - Event ID Statistics
 - Output to CSV to analyze in Timeline Explorer, etc...

## Planned Features

 - SIGMA rule support
 - Custom attack detection rules
 - Remote analysis
 - Logon Statistics

## Usage

At the moment, please use a Windows Powershell 5.1.
You will need local Administrator access for live analysis.

    Analysis Source (Specify one):
        -LiveAnalysis : Creates a timeline based on the live host's log
        -LogFile <path-to-logfile> : Creates a timelime from an offline .evtx file

    Analysis Type (Specify one):
        -AnalyzeNTLM_UsageBasic : Returns basic NTLM usage based on the NTLM Operational log
        -AnalyzeNTLM_UsageDetailed : Returns detailed NTLM usage based on the NTLM Operational log
        -EventID_Statistics : Output event ID statistics
        -LogonTimeline : Output a condensed timeline of user logons based on the Security log

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

## Useful Options

Show event ID statistics to get a grasp of what kind of events there are:

    .\WELA.ps1 -EventID_Statistics

Create a timeline via offline analysis outputted to a GUI in UTC time:

    .\WELA.ps1 -LogFile .\Security.evtx -LogonTimeline -OutputGUI -UTC

Analyze NTLM Operational logs for NTLM usage before disabling it:
    .\WELA.ps1 -AnalyzeNTLM_UsageBasic -LogFile .\DC1-NTLM-Operational.evtx

## Screenshots

Logon Timeline GUI:

![Logon Timeline GUI](/Screenshots/Screenshot-LogonTimelineGUI.png)

Event ID Statistics:

![Event ID Statistics](/Screenshots/Screenshot-EventIDStatistics.png)

Logon Type Summary:

![Logon Type Summary](/Screenshots/Screenshot-LogonTypeSummary.png)

## Related Windows Event Log Threat Hunting Projects

- [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) Attack detection tool written in Python.
- [Chainsaw](https://github.com/countercept/chainsaw) SIGMA based attack detection tool written in Rust.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) Attack detection tool written in Powershell.
- [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) EVTX Attack sample event log files.
- [RustyBlue](https://github.com/Yamato-Security/RustyBlue) Rust port of DeepBlueCLI.
- [SIGMA](SIGMA: https://github.com/SigmaHQ/sigma) SIGMA generic SIEM rules.
- [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) Import evtx files into Security Onion.
- [Zircolite](https://github.com/wagga40/Zircolite) SIGMA based attack detection tool written in Python.

## Contributing

We would love any form of contributing. Pull requests are the best but feature requests, notifying us of bugs, etc... are also very welcome.