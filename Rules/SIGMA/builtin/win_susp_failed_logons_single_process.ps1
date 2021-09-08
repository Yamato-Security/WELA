# Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -and $_.message -match "LogonType.*2") -and  -not ($_.message -match "ProcessName.*-")) }  | select ProcessName, TargetUserName | group ProcessName | foreach { [PSCustomObject]@{'ProcessName'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_failed_logons_single_process";
    $detectedMessage = "Detects failed logins with multiple accounts from a single process on the system.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4625" -and $_.message -match "LogonType.*2") -and -not ($_.message -match "ProcessName.*-")) } | select ProcessName, TargetUserName | group ProcessName | foreach { [PSCustomObject]@{'ProcessName'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} } | sort count -desc | where { $_.count -gt 10 };
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
