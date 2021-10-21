# Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -and $_.message -match "LogonType.*2") -and  -not ($_.message -match "ProcessName.*-")) }  | select ProcessName, TargetUserName | group ProcessName | foreach { [PSCustomObject]@{'ProcessName'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_logons_single_process";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_logons_single_process";
            $detectedMessage = "Detects failed logins with multiple accounts from a single process on the system.";
            $result = $event |  where { (($_.ID -eq "4625" -and $_.message -match "LogonType.*2") -and -not ($_.message -match "ProcessName.*-")) } | select ProcessName, TargetUserName | group ProcessName | foreach { [PSCustomObject]@{'ProcessName' = $_.name; 'Count' = ($_.group.TargetUserName | sort -u).count } } | sort count -desc | where { $_.count -gt 10 };
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
