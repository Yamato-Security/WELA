# Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -and $_.message -match "LogonType.*3") -and  -not ($_.message -match "IpAddress.*-")) }  | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_remote_logons_single_source";
    $detectedMessage = "Detects a source system failing to authenticate against a remote host with multiple users.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4625" -and $_.message -match "LogonType.*3") -and -not ($_.message -match "IpAddress.*-")) } | select IpAddress, TargetUserName | group IpAddress | foreach { [PSCustomObject]@{'IpAddress'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} } | sort count -desc | where { $_.count -gt 10 };
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
