# Get-WinEvent -LogName Security | where {(((($_.ID -eq "4663" -or $_.ID -eq "4656") -and ($_.message -match "0x40" -or $_.message -match "0x1400" -or $_.message -match "0x1000" -or $_.message -match "0x100000" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1438" -or $_.message -match "0x143a" -or $_.message -match "0x1418" -or $_.message -match "0x1f0fff" -or $_.message -match "0x1f1fff" -or $_.message -match "0x1f2fff" -or $_.message -match "0x1f3fff" -or $_.message -match "40" -or $_.message -match "1400" -or $_.message -match "1000" -or $_.message -match "100000" -or $_.message -match "1410" -or $_.message -match "1010" -or $_.message -match "1438" -or $_.message -match "143a" -or $_.message -match "1418" -or $_.message -match "1f0fff" -or $_.message -match "1f1fff" -or $_.message -match "1f2fff" -or $_.message -match "1f3fff") -and $_.message -match "ObjectType.*Process" -and $_.message -match "ObjectName.*.*\lsass.exe") -and  -not ($_.message -match "SubjectUserName.*.*$")) -and  -not ($_.message -match "ProcessName.*C:\Program Files")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lsass_access_non_system_account";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lsass_access_non_system_account";
            $detectedMessage = "Detects potential mimikatz-like tools accessing LSASS from non system account";
            $result = $event |  where { (((($_.ID -eq "4663" -or $_.ID -eq "4656") -and ($_.message -match "0x40" -or $_.message -match "0x1400" -or $_.message -match "0x1000" -or $_.message -match "0x100000" -or $_.message -match "0x1410" -or $_.message -match "0x1010" -or $_.message -match "0x1438" -or $_.message -match "0x143a" -or $_.message -match "0x1418" -or $_.message -match "0x1f0fff" -or $_.message -match "0x1f1fff" -or $_.message -match "0x1f2fff" -or $_.message -match "0x1f3fff" -or $_.message -match "40" -or $_.message -match "1400" -or $_.message -match "1000" -or $_.message -match "100000" -or $_.message -match "1410" -or $_.message -match "1010" -or $_.message -match "1438" -or $_.message -match "143a" -or $_.message -match "1418" -or $_.message -match "1f0fff" -or $_.message -match "1f1fff" -or $_.message -match "1f2fff" -or $_.message -match "1f3fff") -and $_.message -match "ObjectType.*Process" -and $_.message -match "ObjectName.*.*\\lsass.exe") -and -not ($_.message -match "SubjectUserName.*.*$")) -and -not ($_.message -match "ProcessName.*C:\\Program Files")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
