# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "8" -or $_.ID -eq "10") -and $_.message -match "SourceImage.*.*\powershell.exe" -and $_.message -match "TargetImage.*.*\lsass.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_accessing_winapi_in_powershell_credentials_dumping";
    $detectedMessage = "Detects Accessing to lsass.exe by Powershell";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "8" -or $_.ID -eq "10") -and $_.message -match "SourceImage.*.*\powershell.exe" -and $_.message -match "TargetImage.*.*\lsass.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
(.*)Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}