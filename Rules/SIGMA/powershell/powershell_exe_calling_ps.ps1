# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and ($_.message -match "EngineVersion.*2..*" -or $_.message -match "EngineVersion.*4..*" -or $_.message -match "EngineVersion.*5..*") -and $_.message -match "HostVersion.*3..*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_exe_calling_ps";
    $detectedMessage = "Detects PowerShell called from an executable by the version mismatch method"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "400" -and ($_.message -match "EngineVersion.*2..*" -or $_.message -match "EngineVersion.*4..*" -or $_.message -match "EngineVersion.*5..*") -and $_.message -match "HostVersion.*3..*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
