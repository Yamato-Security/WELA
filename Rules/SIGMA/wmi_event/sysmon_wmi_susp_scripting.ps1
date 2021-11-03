# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "19" -or $_.ID -eq "20" -or $_.ID -eq "21")) -and $_.ID -eq "20" -and (($_.message -match "Destination.*.*new-object" -and $_.message -match "Destination.*.*net.webclient" -and $_.message -match "Destination.*.*.downloadstring") -or ($_.message -match "Destination.*.*new-object" -and $_.message -match "Destination.*.*net.webclient" -and $_.message -match "Destination.*.*.downloadfile") -or ($_.message -match "Destination.*.* iex(" -or $_.message -match "Destination.*.*WScript.shell" -or $_.message -match "Destination.*.* -nop " -or $_.message -match "Destination.*.* -noprofile " -or $_.message -match "Destination.*.* -decode " -or $_.message -match "Destination.*.* -enc "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmi_susp_scripting";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_wmi_susp_scripting";
            $detectedMessage = "Detects suspicious scripting in WMI Event Consumers";
            $result = $event |  where { ((($_.ID -eq "19" -or $_.ID -eq "20" -or $_.ID -eq "21")) -and $_.ID -eq "20" -and (($_.message -match "Destination.*.*new-object" -and $_.message -match "Destination.*.*net.webclient" -and $_.message -match "Destination.*.*.downloadstring") -or ($_.message -match "Destination.*.*new-object" -and $_.message -match "Destination.*.*net.webclient" -and $_.message -match "Destination.*.*.downloadfile") -or ($_.message -match "Destination.*.* iex\(" -or $_.message -match "Destination.*.*WScript.shell" -or $_.message -match "Destination.*.* -nop " -or $_.message -match "Destination.*.* -noprofile " -or $_.message -match "Destination.*.* -decode " -or $_.message -match "Destination.*.* -enc "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                result;
                Write-Output $detectedMessage;
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
