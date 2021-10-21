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
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
