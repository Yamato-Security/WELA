# Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectServer.*DS" -and $_.message -match "AccessMask.*0x40000" -and ($_.message -match "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.message -match "domainDNS")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_object_writedac_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_ad_object_writedac_access";
            $detectedMessage = "Detects WRITE_DAC access to a domain object";
            $result = $event |  where { ($_.ID -eq "4662" -and $_.message -match "ObjectServer.*DS" -and $_.message -match "AccessMask.*0x40000" -and ($_.message -match "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.message -match "domainDNS")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
