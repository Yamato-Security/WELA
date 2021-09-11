# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\runonce.exe") -or ($_.message -match "Run Once Wrapper")) -and ($_.message -match "CommandLine.*.* /AlternateShellStartup.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_runonce_execution";
    $detectedMessage = "This rule detects the execution of Run Once task as configured in the registry";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\runonce.exe") -or ($_.message -match "Run Once Wrapper")) -and ($_.message -match "CommandLine.*.* /AlternateShellStartup.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
