# Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectServer.*DS" -and $_.message -match "AccessMask.*0x40000" -and ($_.message -match "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.message -match "domainDNS")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_ad_object_writedac_access";
    $detectedMessage = "Detects WRITE_DAC access to a domain object";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4662" -and $_.message -match "ObjectServer.*DS" -and $_.message -match "AccessMask.*0x40000" -and ($_.message -match "19195a5b-6da0-11d0-afd3-00c04fd930c9" -or $_.message -match "domainDNS")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
