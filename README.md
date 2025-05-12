<div align="center">
 <p>
    <img alt="WELA Logo" src="screenshots/WELA-logo.png" width="20%">
  <h1>
   WELA (Windows Event Log Auditor) ゑ羅
  </h1>
<div align="center">
 [ <b>English</b> ] | [<a href="README-Japanese.md">日本語</a>]
</div>
 </p>
</div>

---

<p align="center">
    <a href="https://github.com/Yamato-Security/wela/commits/main/"><img src="https://img.shields.io/github/commit-activity/t/Yamato-Security/wela/main" /></a>
    <a href="https://twitter.com/SecurityYamato"><img src="https://img.shields.io/twitter/follow/SecurityYamato?style=social"/></a>
</p>


# About WELA
Windows Event Log Auditor

# Companion Projects

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) A guide for Windows Event Log settings.
* [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide) A guide to creating a baseline of Windows Event Logs Audit Settings.
* [WELA-RulesGenerator](https://github.com/Yamato-Security/WELA-RulesGenerator) A tool for generating Sigma rules from Windows Event Log settings.

# Table of Contents

- [About WELA](#about-wela)
- [Companion Projects](#companion-projects)
- [Table of Contents](#table-of-contents)
- [Screenshots](#screenshots)
- [Features](#features)
- [Downloads](#downloads)
- [Command List](#command-list)
- [Contribution](#contribution)
- [Bug Submission](#bug-submission)
- [License](#license)
- [Contributors](#contributors)
- [Acknowledgements](#acknowledgements)
- [Twitter](#twitter)

# Screenshots

## Startup
![WELA Startup](screenshots/startup.png)

## audit-settings (stdout)
![WELA Stdout](screenshots/stdout.png)
## audit-settings (gui)
![WELA GUI](screenshots/gui.png)

## audit-settings (table)
![WELA Table](screenshots/table.png)

## audit-filesize
![WELA FileSize](screenshots/filesize.png)

# Features

# Prerequisites
* PowerShell 5.1+
* Run PowerShell with Administrator privileges

# Downloads

Please download the latest stable version of WELA from the [Releases](https://github.com/Yamato-Security/wela/releases) page.

# Running WELA
1. Unzip the [release zip file](https://github.com/Yamato-Security/wela/releases).
2. Open PowerShell with **Administrator privileges**.
3. `./WELA.ps1 help` to run WELA.

# Command List
* `audit-settings`: Audit Windows Event Log settings
* `audit-filesize`: Audit Windows Event Log file sizes
* `update-rules` : Update Sigma contents in config directory

# Command Usage
## audit-settings
## audit-filesize
## update-rules

# Other Windows Event Log Audit Related Resources

* [Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
* [Windows event logging and forwarding](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding)
* [A Data-Driven Approach to Windows Advanced Audit Policy – What to Enable and Why](https://www.splunk.com/en_us/blog/security/windows-audit-policy-guide.html)

# Contribution

We would love any form of contribution.
Pull requests, rule creation and sample logs are the best, but feature requests notifying us of bugs, etc... are also very welcome.

At the least, **if you like our tools and resources, then please give us a star on GitHub and show your support!**

# Bug Submission

* Please submit any bugs you find [here.](https://github.com/Yamato-Security/wela/issues/new?assignees=&labels=bug&template=bug_report.md&title=%5Bbug%5D)
* This project is currently actively maintained, and we are happy to fix any bugs reported.

# License

* WELA is released under [MIT License]()

# Contributors

* Fukusuke Takahashi (core developer)
* Zach Mathis (project leader, tool design, testing, etc...) (@yamatosecurity)

# Twitter

You can receive the latest news about WELA, rule updates, other Yamato Security tools, etc... by following us on Twitter at [@SecurityYamato](https://twitter.com/SecurityYamato).