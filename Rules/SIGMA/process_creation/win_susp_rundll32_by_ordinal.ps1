# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\rundll32.exe.*" -and $_.message -match "CommandLine.*.*,#.*") -and  -not ($_.message -match "CommandLine.*.*EDGEHTML.dll.*" -and $_.message -match "CommandLine.*.*#141.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_rundll32_by_ordinal";
    $detectedMessage = "Detects suspicious calls of DLLs in rundll32.dll exports by ordinal"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\rundll32.exe.*" -and $_.message -match "CommandLine.*.*,#.*") -and -not ($_.message -match "CommandLine.*.*EDGEHTML.dll.*" -and $_.message -match "CommandLine.*.*#141.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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