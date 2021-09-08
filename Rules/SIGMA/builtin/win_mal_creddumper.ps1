# Get-WinEvent -LogName System | where {((($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "6") -and (($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {((($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_mal_creddumper";
    $detectedMessage = "Detects well-known credential dumping tools execution via service execution events";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ((($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { (($_.ID -eq "6") -and (($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ((($_.message -match "ServiceName.*.*fgexec.*" -or $_.message -match "ServiceName.*.*wceservice.*" -or $_.message -match "ServiceName.*.*wce service.*" -or $_.message -match "ServiceName.*.*pwdump.*" -or $_.message -match "ServiceName.*.*gsecdump.*" -or $_.message -match "ServiceName.*.*cachedump.*" -or $_.message -match "ServiceName.*.*mimikatz.*" -or $_.message -match "ServiceName.*.*mimidrv.*") -or ($_.message -match "ImagePath.*.*fgexec.*" -or $_.message -match "ImagePath.*.*dumpsvc.*" -or $_.message -match "ImagePath.*.*cachedump.*" -or $_.message -match "ImagePath.*.*mimidrv.*" -or $_.message -match "ImagePath.*.*gsecdump.*" -or $_.message -match "ImagePath.*.*servpw.*" -or $_.message -match "ImagePath.*.*pwdump.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
