# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\\msiexec.exe" -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_msiexec_cwd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_msiexec_cwd";
            $detectedMessage = "Detects suspicious msiexec process starts in an uncommon directory";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "Image.*.*\\msiexec.exe" -and -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
