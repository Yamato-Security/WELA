# Get-WinEvent -LogName Security | where {(($_.ID -eq "4771" -and $_.message -match "Status.*0x18") -and  -not ($_.message -match "TargetUserName.*.*$")) }  | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_logons_single_source_kerberos";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_logons_single_source_kerberos";
            $detectedMessage = "Detects multiple failed logins with multiple valid domain accounts from a single source system using the Kerberos protocol.";
            $result = $event |  where { (($_.ID -eq "4771" -and $_.message -match "Status.*0x18") -and -not ($_.message -match "TargetUserName.*.*$")) } | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress' = $_.name; 'Count' = ($_.group.TargetUserName | sort -u).count } } | sort count -desc | where { $_.count -gt 10 };
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
