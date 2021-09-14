# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\msdtc.exe" -or $_.message -match "Image.*.*\gpvc.exe") -and  -not (($_.message -match "Image.*C:\Windows\System32\.*" -or $_.message -match "Image.*C:\Windows\SysWOW64\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_session_highjack";
    $detectedMessage = "Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\msdtc.exe" -or $_.message -match "Image.*.*\gpvc.exe") -and -not (($_.message -match "Image.*C:\Windows\System32\.*" -or $_.message -match "Image.*C:\Windows\SysWOW64\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
