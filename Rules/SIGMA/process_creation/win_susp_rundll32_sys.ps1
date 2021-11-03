# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe" -and ($_.message -match "CommandLine.*.*.sys," -or $_.message -match "CommandLine.*.*.sys ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_sys";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rundll32_sys";
            $detectedMessage = "Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe" -and ($_.message -match "CommandLine.*.*.sys," -or $_.message -match "CommandLine.*.*.sys ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
