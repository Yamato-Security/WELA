# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*rundll32.exe.*" -and $_.message -match "CommandLine.*.*%APPDATA%\.*") -and ($_.message -match "CommandLine.*.*.dat",.*" -or $_.message -match "CommandLine.*.*.dll",#1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_sofacy";
    $detectedMessage = "Detects Trojan loader acitivty as used by APT28";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*rundll32.exe.*" -and $_.message -match "CommandLine.*.*%APPDATA%\\.*") -and ($_.message -match "CommandLine.*.*.dat.*" -or $_.message -match "CommandLine.*.*.dll#1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
