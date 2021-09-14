# Get-WinEvent -LogName Security | where {(($_.ID -eq "4768" -and $_.message -match "Status.*0x12") -and  -not ($_.message -match "TargetUserName.*.*$")) }  | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_logons_single_source_kerberos2";
    $detectedMessage = "Detects failed logins with multiple disabled domain accounts from a single source system using the Kerberos protocol.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4768" -and $_.message -match "Status.*0x12") -and -not ($_.message -match "TargetUserName.*.*$")) } | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} } | sort count -desc | where { $_.count -gt 10 };
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
