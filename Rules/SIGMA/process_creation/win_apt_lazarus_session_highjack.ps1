# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\msdtc.exe" -or $_.message -match "Image.*.*\gpvc.exe") -and  -not (($_.message -match "Image.*C:\Windows\System32\" -or $_.message -match "Image.*C:\Windows\SysWOW64\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_session_highjack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_lazarus_session_highjack";
            $detectedMessage = "Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\msdtc.exe" -or $_.message -match "Image.*.*\\gpvc.exe") -and -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
