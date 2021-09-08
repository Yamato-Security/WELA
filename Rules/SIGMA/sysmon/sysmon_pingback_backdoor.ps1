# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*.*updata.exe" -and $_.message -match "TargetFilename.*C:\\Windows\\oci.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*msdtc.exe" -and $_.message -match "ImageLoaded.*C:\\Windows\\oci.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*updata.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*msdtc.*" -and $_.message -match "CommandLine.*.*start.*" -and $_.message -match "CommandLine.*.*auto.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_pingback_backdoor";
    $detectedMessage = "Detects the use of Pingback backdoor that creates ICMP tunnel for C2 as described in the trustwave report";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "11" -and $_.message -match "Image.*.*updata.exe" -and $_.message -match "TargetFilename.*C:\\Windows\\oci.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $result2 = $event | where { ($_.ID -eq "7" -and $_.message -match "Image.*.*msdtc.exe" -and $_.message -match "ImageLoaded.*C:\\Windows\\oci.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $result3 = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*updata.exe" -and $_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*msdtc.*" -and $_.message -match "CommandLine.*.*start.*" -and $_.message -match "CommandLine.*.*auto.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
            if (($result.Count -ne 0) -or ($result2.Count -ne 0) -or ($result3.Count -ne 0)) {
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
