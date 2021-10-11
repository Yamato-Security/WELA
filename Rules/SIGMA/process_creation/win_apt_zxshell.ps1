# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\rundll32.exe") -and ($_.message -match "CommandLine.*.*zxFunction.*" -or $_.message -match "CommandLine.*.*RemoteDiskXXXXX.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_zxshell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_zxshell";
            $detectedMessage = "Detects a ZxShell start by the called and well-known function name";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\rundll32.exe") -and ($_.message -match "CommandLine.*.*zxFunction.*" -or $_.message -match "CommandLine.*.*RemoteDiskXXXXX.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
