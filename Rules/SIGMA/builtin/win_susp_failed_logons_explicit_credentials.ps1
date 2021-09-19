# Get-WinEvent -LogName Security | where {($_.ID -eq "4648") }  | select ComputerName, Account_Name | group ComputerName | foreach { [PSCustomObject]@{'ComputerName'=$_.name;'Count'=($_.group.Account_Name | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {

    $ruleName = "win_susp_failed_logons_explicit_credentials";
    $detectedMessage = "Detects a source user failing to authenticate with multiple users using explicit credentials on a host.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4648") } | select ComputerName, Account_Name | group ComputerName | foreach { [PSCustomObject]@{'ComputerName'=$_.name;'Count'=($_.group.Account_Name | sort -u).count} } | sort count -desc | where { $_.count -gt 10 };
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
