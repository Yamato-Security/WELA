# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\cscript.exe" -and $_.message -match "CommandLine.*.*.vbs.*" -and $_.message -match "CommandLine.*.*/shell.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_cloudhopper";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_apt_cloudhopper";
                    $detectedMessage = "Detects suspicious file execution by wscript and cscript";
                $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cscript.exe" -and $_.message -match "CommandLine.*.*.vbs.*" -and $_.message -match "CommandLine.*.*/shell.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
