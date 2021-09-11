# Get-WinEvent -LogName System | where {($_.ID -eq "1033" -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_dhcp_config";
    $detectedMessage = "This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1033" -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
