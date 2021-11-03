# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\sqldumper.exe" -and ($_.message -match "CommandLine.*.*0x0110" -or $_.message -match "CommandLine.*.*0x01100:40")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_sqldumper_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_sqldumper_activity";
            $detectedMessage = "Detects process dump via legitimate sqldumper.exe binary";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\sqldumper.exe" -and ($_.message -match "CommandLine.*.*0x0110" -or $_.message -match "CommandLine.*.*0x01100:40")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
