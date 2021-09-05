# Get-WinEvent -LogName Security | where {(($_.ID -eq "529" -or $_.ID -eq "4625") -and $_.message -match "TargetUserName.*.*" -and $_.message -match "WorkstationName.*.*") }  | select WorkstationName, TargetUserName | group WorkstationName | foreach { [PSCustomObject]@{'WorkstationName'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 3 }

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_failed_logons_single_source";
    $detectedMessage = "Detects suspicious failed logins with different user accounts from a single source system"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "529" -or $_.ID -eq "4625") -and $_.message -match "TargetUserName.*.*" -and $_.message -match "WorkstationName.*.*") } | select WorkstationName, TargetUserName | group WorkstationName | foreach { [PSCustomObject]@{'WorkstationName'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} } | sort count -desc | where { $_.count -gt 3 };
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
