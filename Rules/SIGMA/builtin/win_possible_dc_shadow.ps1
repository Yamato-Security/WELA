# Get-WinEvent -LogName Security | where {((($_.ID -eq "4742" -and $_.message -match "ServicePrincipalNames.*.*GC/") -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*servicePrincipalName" -and $_.message -match "AttributeValue.*GC/"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_possible_dc_shadow";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_possible_dc_shadow";
            $detectedMessage = "Detects DCShadow via create new SPN";
            $result = $event | where { ((($_.ID -eq "4742" -and $_.message -match "ServicePrincipalNames.*.*GC/") -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*servicePrincipalName" -and $_.message -match "AttributeValue.*GC/"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
