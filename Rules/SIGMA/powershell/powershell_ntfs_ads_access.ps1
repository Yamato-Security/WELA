# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "set-content" -or $_.message -match "add-content") -and $_.message -match "-stream") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_ntfs_ads_access";
    $detectedMessage = "Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.message -match "set-content" -or $_.message -match "add-content") -and $_.message -match "-stream") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
