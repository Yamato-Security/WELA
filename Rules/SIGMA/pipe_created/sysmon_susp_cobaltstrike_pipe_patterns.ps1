# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*\mojo.5688.8052.183894939787088877.*" -or $_.message -match "PipeName.*\mojo.5688.8052.35780273329370473.*" -or $_.message -match "PipeName.*\mypipe-f.*" -or $_.message -match "PipeName.*\mypipe-h.*" -or $_.message -match "PipeName.*\ntsvcs_.*" -or $_.message -match "PipeName.*\scerpc_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_cobaltstrike_pipe_patterns";
    $detectedMessage = "Detects the creation of a named pipe with a pattern found in CobaltStrike malleable C2 profiles"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*\mojo.5688.8052.183894939787088877.*" -or $_.message -match "PipeName.*\mojo.5688.8052.35780273329370473.*" -or $_.message -match "PipeName.*\mypipe-f.*" -or $_.message -match "PipeName.*\mypipe-h.*" -or $_.message -match "PipeName.*\ntsvcs_.*" -or $_.message -match "PipeName.*\scerpc_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
