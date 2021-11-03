# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\mhsta.exe" -and (((($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\cmd.exe" -or $_.message -match "ParentImage.*.*\\powershell.exe") -or ($_.message -match "CommandLine.*.*\\AppData\\Local" -or $_.message -match "CommandLine.*.*C:\\Windows\\Temp" -or $_.message -match "CommandLine.*.*C:\\Users\\Public"))) -or (($_.ID -eq "1") -and  -not (($_.message -match "Image.*.*C:\\Windows\\System32" -or $_.message -match "Image.*.*C:\\Windows\\SysWOW64")))) -or (($_.ID -eq "1") -and  -not (($_.message -match "CommandLine.*.*.htm" -or $_.message -match "CommandLine.*.*.hta") -and ($_.message -match "CommandLine.*.*mshta.exe" -or $_.message -match "CommandLine.*.*mshta"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_mshta_pattern";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_mshta_pattern";
            $detectedMessage = "Detects suspicious mshta process patterns";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\mhsta.exe" -and (((($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\cmd.exe" -or $_.message -match "ParentImage.*.*\\powershell.exe") -or ($_.message -match "CommandLine.*.*\\AppData\\Local" -or $_.message -match "CommandLine.*.*C:\\Windows\\Temp" -or $_.message -match "CommandLine.*.*C:\\Users\\Public"))) -or (($_.ID -eq "1") -and -not (($_.message -match "Image.*.*C:\\Windows\\System32" -or $_.message -match "Image.*.*C:\\Windows\\SysWOW64")))) -or (($_.ID -eq "1") -and -not (($_.message -match "CommandLine.*.*.htm" -or $_.message -match "CommandLine.*.*.hta") -and ($_.message -match "CommandLine.*.*mshta.exe" -or $_.message -match "CommandLine.*.*mshta"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
