# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*C:\Windows\SysWOW64\cmd.exe" -and $_.message -match "CommandLine.*.*\Windows\Caches\NavShExt.dll ") -or $_.message -match "CommandLine.*.*\AppData\Roaming\MICROS~1\Windows\Caches\NavShExt.dll,Setting")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_elise";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_elise";
            $detectedMessage = "Detects Elise backdoor acitivty as used by APT32";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*C:\\Windows\\SysWOW64\\cmd.exe" -and $_.message -match "CommandLine.*.*\\Windows\\Caches\\NavShExt.dll ") -or $_.message -match "CommandLine.*.*\\AppData\\Roaming\\MICROS~1\\Windows\\Caches\\NavShExt.dll,Setting")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
