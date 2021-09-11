# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and ($_.ID -eq "11") -and ((($_.message -match "TargetFilename.*.*\Microsoft\Word\Startup\.*" -and $_.message -match "TargetFilename.*.*.wll") -or ($_.message -match "TargetFilename.*.*\Microsoft\Excel\Startup\.*" -and $_.message -match "TargetFilename.*.*.xll")) -or ($_.message -match "TargetFilename.*.*\Microsoft\Addins\.*" -and ($_.message -match "TargetFilename.*.*.xlam" -or $_.message -match "TargetFilename.*.*.xla")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_office_persistence";
    $detectedMessage = "Detects add-ins that load when Microsoft Word or Excel starts (.wll/.xll are simply .dll fit for Word or Excel).";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "11") -and ($_.ID -eq "11") -and ((($_.message -match "TargetFilename.*.*\Microsoft\Word\Startup\.*" -and $_.message -match "TargetFilename.*.*.wll") -or ($_.message -match "TargetFilename.*.*\Microsoft\Excel\Startup\.*" -and $_.message -match "TargetFilename.*.*.xll")) -or ($_.message -match "TargetFilename.*.*\Microsoft\Addins\.*" -and ($_.message -match "TargetFilename.*.*.xlam" -or $_.message -match "TargetFilename.*.*.xla")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
