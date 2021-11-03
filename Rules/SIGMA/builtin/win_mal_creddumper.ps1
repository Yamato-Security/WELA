# Get-WinEvent -LogName System | where {((($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "6") -and (($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {((($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mal_creddumper";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ((($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "6") -and (($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ((($_.message -match "ServiceName.*.*fgexec" -or $_.message -match "ServiceName.*.*wceservice" -or $_.message -match "ServiceName.*.*wce service" -or $_.message -match "ServiceName.*.*pwdump" -or $_.message -match "ServiceName.*.*gsecdump" -or $_.message -match "ServiceName.*.*cachedump" -or $_.message -match "ServiceName.*.*mimikatz" -or $_.message -match "ServiceName.*.*mimidrv") -or ($_.message -match "ImagePath.*.*fgexec" -or $_.message -match "ImagePath.*.*dumpsvc" -or $_.message -match "ImagePath.*.*cachedump" -or $_.message -match "ImagePath.*.*mimidrv" -or $_.message -match "ImagePath.*.*gsecdump" -or $_.message -match "ImagePath.*.*servpw" -or $_.message -match "ImagePath.*.*pwdump"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);

            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
