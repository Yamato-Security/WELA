# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*psexec.*" -or $_.message -match "PipeName.*paexec.*" -or $_.message -match "PipeName.*remcom.*" -or $_.message -match "PipeName.*csexec.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_psexec_pipes_artifacts";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*psexec.*" -or $_.message -match "PipeName.*paexec.*" -or $_.message -match "PipeName.*remcom.*" -or $_.message -match "PipeName.*csexec.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}