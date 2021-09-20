# Get-WinEvent -LogName Microsoft-Windows-WMI-Activity/Operational | where { ((($_.ID -eq "5861" -and ($_.message -match ".*ActiveScriptEventConsumer.*" -or $_.message -match ".*CommandLineEventConsumer.*" -or $_.message -match ".*CommandLineTemplate.*")) -or $_.ID -eq "5859")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Security | where { ($_.ID -eq "4662" -and $_.message -match "ObjectType.*WMI Namespace" -and $_.message -match "ObjectName.*.*subscription.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_wmi_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            
            $results += $event | where { ((($_.ID -eq "5861" -and ($_.message -match ".*ActiveScriptEventConsumer.*" -or $_.message -match ".*CommandLineEventConsumer.*" -or $_.message -match ".*CommandLineTemplate.*")) -or $_.ID -eq "5859")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "4662" -and $_.message -match "ObjectType.*WMI Namespace" -and $_.message -match "ObjectName.*.*subscription.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $entry.Value
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
