# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*.*updata.exe" -and $_.message -match "TargetFilename.*C:\\Windows\\oci.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*msdtc.exe" -and $_.message -match "ImageLoaded.*C:\\Windows\\oci.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*updata.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*msdtc.*" -and $_.message -match "CommandLine.*.*start.*" -and $_.message -match "CommandLine.*.*auto.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_pingback_backdoor";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "sysmon_pingback_backdoor";
            $detectedMessage = "Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report";
            $results = @();
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "Image.*.*updata.exe" -and $_.message -match "TargetFilename.*C:\\Windows\\oci.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "7" -and $_.message -match "Image.*.*msdtc.exe" -and $_.message -match "ImageLoaded.*C:\\Windows\\oci.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*updata.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*msdtc.*" -and $_.message -match "CommandLine.*.*start.*" -and $_.message -match "CommandLine.*.*auto.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
