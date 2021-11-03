# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and ($_.message -match "SourceImage.*.*\System32\cscript.exe" -or $_.message -match "SourceImage.*.*\System32\wscript.exe" -or $_.message -match "SourceImage.*.*\System32\mshta.exe" -or $_.message -match "SourceImage.*.*\winword.exe" -or $_.message -match "SourceImage.*.*\excel.exe") -and $_.message -match "TargetImage.*.*\SysWOW64\" -and -not StartModule="*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cactustorch";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cactustorch";
            $detectedMessage = "Detects remote thread creation from CACTUSTORCH as described in references.";
            $result = $event |  where { ($_.ID -eq "8" -and ($_.message -match "SourceImage.*.*\\System32\\cscript.exe" -or $_.message -match "SourceImage.*.*\\System32\\wscript.exe" -or $_.message -match "SourceImage.*.*\\System32\\mshta.exe" -or $_.message -match "SourceImage.*.*\\winword.exe" -or $_.message -match "SourceImage.*.*\\excel.exe") -and $_.message -match "TargetImage.*.*\\SysWOW64\\" -and (-not $_.message -match "StartModule")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
