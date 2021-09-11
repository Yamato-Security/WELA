# Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\SOFTWARE\Microsoft\.NETFramework" -and $_.message -match "ObjectValueName.*ETWEnabled" -and $_.message -match "NewValue.*0") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_etw_modification";
    $detectedMessage = "Potential adversaries stopping ETW providers recording loaded .NET assemblies.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\SOFTWARE\Microsoft\.NETFramework" -and $_.message -match "ObjectValueName.*ETWEnabled" -and $_.message -match "NewValue.*0") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
