# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and ($_.message -match "5985" -or $_.message -match "5986") -and $_.message -match "LayerRTID.*44") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_remote_powershell_session";
    $detectedMessage = "Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5156" -and ($_.message -match "5985" -or $_.message -match "5986") -and $_.message -match "LayerRTID.*44") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
