# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\.*" -and $_.message -match "TargetObject.*.*_Classes\exefile\shell\runas\command\isolatedCommand") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_uac_bypass_sdclt";
    $detectedMessage = "Detects changes to HKCU:SoftwareClassesexefileshell
unasmmandisolatedCommand"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\.*" -and $_.message -match "TargetObject.*.*_Classes\exefile\shell\runas\command\isolatedCommand") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result; $result; ected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
