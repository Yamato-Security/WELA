# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and ($_.message -match "5985" -or $_.message -match "5986") -and $_.message -match "LayerRTID.*44") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_remote_powershell_session";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_remote_powershell_session";
            $detectedMessage = "Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986";
            $result = $event |  where { ($_.ID -eq "5156" -and ($_.message -match "5985" -or $_.message -match "5986") -and $_.message -match "LayerRTID.*44") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($null -ne $result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
