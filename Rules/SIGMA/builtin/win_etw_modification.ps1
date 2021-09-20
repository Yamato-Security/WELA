# Get-WinEvent -LogName Security | where {($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\SOFTWARE\Microsoft\.NETFramework" -and $_.message -match "ObjectValueName.*ETWEnabled" -and $_.message -match "NewValue.*0") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_etw_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_etw_modification";
            $detectedMessage = "Potential adversaries stopping ETW providers recording loaded .NET assemblies.";
            $result = $event |  where { ($_.ID -eq "4657" -and $_.message -match "ObjectName.*.*\\SOFTWARE\\Microsoft\\.NETFramework" -and $_.message -match "ObjectValueName.*ETWEnabled" -and $_.message -match "NewValue.*0") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
