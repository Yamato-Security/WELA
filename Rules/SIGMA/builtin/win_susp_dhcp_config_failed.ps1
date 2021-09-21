# Get-WinEvent -LogName System | where {(($_.ID -eq "1031" -or $_.ID -eq "1032" -or $_.ID -eq "1034") -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_dhcp_config_failed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_dhcp_config_failed";
            $detectedMessage = "This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded";
            $result = $event |  where { (($_.ID -eq "1031" -or $_.ID -eq "1032" -or $_.ID -eq "1034") -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
