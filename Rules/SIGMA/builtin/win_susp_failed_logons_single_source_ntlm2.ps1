# Get-WinEvent -LogName Security | where {(($_.ID -eq "4776" -and $_.message -match "Status.*.*0xC0000064") -and  -not ($_.message -match "TargetUserName.*.*$")) }  | select Workstation, TargetUserName | group Workstation | foreach { [PSCustomObject]@{'Workstation'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_failed_logons_single_source_ntlm2";
    $detectedMessage = "Detects failed logins with multiple invalid domain accounts from a single source system using the NTLM protocol."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4776" -and $_.message -match "Status.*.*0xC0000064") -and -not ($_.message -match "TargetUserName.*.*$")) } | select Workstation, TargetUserName | group Workstation | foreach { [PSCustomObject]@{'Workstation'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} } | sort count -desc | where { $_.count -gt 10 };
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