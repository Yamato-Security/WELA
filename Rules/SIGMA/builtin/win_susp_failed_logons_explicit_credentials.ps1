# Get-WinEvent -LogName Security | where {($_.ID -eq "4648") }  | select ComputerName, Account_Name | group ComputerName | foreach { [PSCustomObject]@{'ComputerName'=$_.name;'Count'=($_.group.Account_Name | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_logons_explicit_credentials";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_logons_explicit_credentials";
            $detectedMessage = "Detects a source user failing to authenticate with multiple users using explicit credentials on a host.";
            $result = $event |  where { ($_.ID -eq "4648") } | select ComputerName, Account_Name | group ComputerName | foreach { [PSCustomObject]@{'ComputerName' = $_.name; 'Count' = ($_.group.Account_Name | sort -u).count } } | sort count -desc | where { $_.count -gt 10 };
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
