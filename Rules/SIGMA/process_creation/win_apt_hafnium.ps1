# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*attrib" -and $_.message -match "CommandLine.*.* +h " -and $_.message -match "CommandLine.*.* +s " -and $_.message -match "CommandLine.*.* +r " -and $_.message -match "CommandLine.*.*.aspx") -or ($_.message -match "CommandLine.*.*schtasks" -and $_.message -match "CommandLine.*.*VSPerfMon") -or ($_.message -match "CommandLine.*.*vssadmin list shadows" -and $_.message -match "CommandLine.*.*Temp\__output") -or $_.message -match "CommandLine.*.*%TEMP%\execute.bat" -or $_.message -match "Image.*.*Users\Public\opera\Opera_browser.exe" -or ($_.message -match "Image.*.*Opera_browser.exe" -and ($_.message -match "ParentImage.*.*\services.exe" -or $_.message -match "ParentImage.*.*\svchost.exe")) -or $_.message -match "Image.*.*\ProgramData\VSPerfMon\" -or ($_.message -match "CommandLine.*.* -t7z " -and $_.message -match "CommandLine.*.*C:\Programdata\pst" -and $_.message -match "CommandLine.*.*\it.zip") -or ($_.message -match "Image.*.*\makecab.exe" -and ($_.message -match "CommandLine.*.*Microsoft\Exchange Server\" -or $_.message -match "CommandLine.*.*inetpub\wwwroot")) -or ($_.message -match "CommandLine.*.*\Temp\xx.bat" -or $_.message -match "CommandLine.*.*Windows\WwanSvcdcs" -or $_.message -match "CommandLine.*.*Windows\Temp\cw.exe") -or ($_.message -match "CommandLine.*.*\comsvcs.dll" -and $_.message -match "CommandLine.*.*Minidump" -and $_.message -match "CommandLine.*.*\inetpub\wwwroot") -or ($_.message -match "CommandLine.*.*dsquery" -and $_.message -match "CommandLine.*.* -uco " -and $_.message -match "CommandLine.*.*\inetpub\wwwroot"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_hafnium";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_hafnium";
            $detectedMessage = "Detects activity observed by different researchers to be HAFNIUM group acitivity (or related) on Exchange servers";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*attrib" -and $_.message -match "CommandLine.*.* +h " -and $_.message -match "CommandLine.*.* +s " -and $_.message -match "CommandLine.*.* +r " -and $_.message -match "CommandLine.*.*.aspx") -or ($_.message -match "CommandLine.*.*schtasks" -and $_.message -match "CommandLine.*.*VSPerfMon") -or ($_.message -match "CommandLine.*.*vssadmin list shadows" -and $_.message -match "CommandLine.*.*Temp\\__output") -or $_.message -match "CommandLine.*.*%TEMP%\\execute.bat" -or $_.message -match "Image.*.*Users\\Public\\opera\\Opera_browser.exe" -or ($_.message -match "Image.*.*Opera_browser.exe" -and ($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe")) -or $_.message -match "Image.*.*\\ProgramData\\VSPerfMon\\" -or ($_.message -match "CommandLine.*.* -t7z " -and $_.message -match "CommandLine.*.*C:\\Programdata\\pst" -and $_.message -match "CommandLine.*.*\\it.zip") -or ($_.message -match "Image.*.*\\makecab.exe" -and ($_.message -match "CommandLine.*.*Microsoft\\Exchange Server\\" -or $_.message -match "CommandLine.*.*inetpub\\wwwroot")) -or ($_.message -match "CommandLine.*.*\\Temp\\xx.bat" -or $_.message -match "CommandLine.*.*Windows\\WwanSvcdcs" -or $_.message -match "CommandLine.*.*Windows\\Temp\\cw.exe") -or ($_.message -match "CommandLine.*.*\\comsvcs.dll" -and $_.message -match "CommandLine.*.*Minidump" -and $_.message -match "CommandLine.*.*\\inetpub\\wwwroot") -or ($_.message -match "CommandLine.*.*dsquery" -and $_.message -match "CommandLine.*.* -uco " -and $_.message -match "CommandLine.*.*\\inetpub\\wwwroot"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
