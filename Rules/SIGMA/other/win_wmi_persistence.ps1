# Get-WinEvent -LogName Microsoft-Windows-WMI-Activity/Operational | where { ((($_.ID -eq "5861" -and ($_.message -match "ActiveScriptEventConsumer" -or $_.message -match "CommandLineEventConsumer" -or $_.message -match "CommandLineTemplate")) -or $_.ID -eq "5859")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Security | where { ($_.ID -eq "4662" -and $_.message -match "ObjectType.*WMI Namespace" -and $_.message -match "ObjectName.*.*subscription") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_wmi_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_wmi_persistence";
            $detectedMessage = "Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ((($_.ID -eq "5861" -and ($_.message -match "ActiveScriptEventConsumer" -or $_.message -match "CommandLineEventConsumer" -or $_.message -match "CommandLineTemplate")) -or $_.ID -eq "5859")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4662" -and $_.message -match "ObjectType.*WMI Namespace" -and $_.message -match "ObjectName.*.*subscription") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result
                    Write-Output ""; 
                }
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
