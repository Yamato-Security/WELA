# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*esentutl" -and $_.message -match "CommandLine.*.* /p") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_susp_esentutl_params";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_susp_esentutl_params";
            $detectedMessage = "Conti recommendation to its affiliates to use esentult to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*esentutl" -and $_.message -match "CommandLine.*.* /p") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

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
