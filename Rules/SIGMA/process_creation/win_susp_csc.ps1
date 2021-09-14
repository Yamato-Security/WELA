# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\csc.exe" -and ($_.message -match "ParentImage.*.*\wscript.exe" -or $_.message -match "ParentImage.*.*\cscript.exe" -or $_.message -match "ParentImage.*.*\mshta.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_csc";
    $detectedMessage = "Detects a suspicious parent of csc.exe, which could by a sign of payload delivery";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\csc.exe" -and ($_.message -match "ParentImage.*.*\wscript.exe" -or $_.message -match "ParentImage.*.*\cscript.exe" -or $_.message -match "ParentImage.*.*\mshta.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
