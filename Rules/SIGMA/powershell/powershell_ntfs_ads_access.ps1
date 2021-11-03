# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "set-content" -or $_.message -match "add-content") -and $_.message -match "-stream") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_ntfs_ads_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_ntfs_ads_access";
            $detectedMessage = "Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.";
            $result = $event |  where { (($_.message -match "set-content" -or $_.message -match "add-content") -and $_.message -match "-stream") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
