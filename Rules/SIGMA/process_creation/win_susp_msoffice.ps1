# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\excel.exe") -and $_.message -match "CommandLine.*.*http.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_msoffice";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_msoffice";
            $detectedMessage = "Downloads payload from remote server";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\excel.exe") -and $_.message -match "CommandLine.*.*http.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
