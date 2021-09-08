# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Description.*Execute processes remotely" -and $_.message -match "Product.*Sysinternals PsExec") -and  -not (($_.message -match "Image.*.*\PsExec.exe" -or $_.message -match "Image.*.*\PsExec64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_renamed_psexec";
    $detectedMessage = "Detects the execution of a renamed PsExec often used by attackers or malware";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "Description.*Execute processes remotely" -and $_.message -match "Product.*Sysinternals PsExec") -and -not (($_.message -match "Image.*.*\PsExec.exe" -or $_.message -match "Image.*.*\PsExec64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
