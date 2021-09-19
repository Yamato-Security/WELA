# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "ImageLoaded.*.*\\ttdrecord.dll" -or $_.message -match "ImageLoaded.*.*\\ttdwriter.dll" -or $_.message -match "ImageLoaded.*.*\\ttdloader.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\tttracer.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_tttracer_mod_load";
    $detectedMessage = "Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "7" -and ($_.message -match "ImageLoaded.*.*\\ttdrecord.dll" -or $_.message -match "ImageLoaded.*.*\\ttdwriter.dll" -or $_.message -match "ImageLoaded.*.*\\ttdloader.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\tttracer.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
