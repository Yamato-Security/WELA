# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe.*" -and $_.message -match "CommandLine.*.*.dll.*" -and $_.message -match "CommandLine.*.*StartNodeRelay.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_c3_load_by_rundll32";
    $detectedMessage = "F-Secure C3 produces DLLs with a default exported StartNodeRelay function.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*rundll32.exe.*" -and $_.message -match "CommandLine.*.*.dll.*" -and $_.message -match "CommandLine.*.*StartNodeRelay.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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