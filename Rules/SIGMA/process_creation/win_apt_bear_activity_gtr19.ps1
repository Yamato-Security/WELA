# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\xcopy.exe" -and $_.message -match "CommandLine.*.*/S" -and $_.message -match "CommandLine.*.*/E" -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*/Q" -and $_.message -match "CommandLine.*.*/H" -and $_.message -match "CommandLine.*.*\") -or ($_.message -match "Image.*.*\adexplorer.exe" -and $_.message -match "CommandLine.*.*-snapshot" -and $_.message -match "CommandLine.*""" -and $_.message -match "CommandLine.*.*c:\users\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_bear_activity_gtr19";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_bear_activity_gtr19";
            $detectedMessage = "Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\xcopy.exe" -and $_.message -match "CommandLine.*.*/S" -and $_.message -match "CommandLine.*.*/E" -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*/Q" -and $_.message -match "CommandLine.*.*/H" -and $_.message -match "CommandLine.*.*\\") -or ($_.message -match "Image.*.*\\adexplorer.exe" -and $_.message -match "CommandLine.*.*-snapshot" -and $_.message -match "CommandLine.*""" -and $_.message -match "CommandLine.*.*c:\\users\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
