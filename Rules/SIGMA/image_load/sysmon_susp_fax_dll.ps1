# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and (($_.message -match "Image.*.*fxssvc.exe") -and ($_.message -match "ImageLoaded.*.*ualapi.dll")) -and  -not (($_.message -match "ImageLoaded.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_fax_dll";
    $detectedMessage = "The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and (($_.message -match "Image.*.*fxssvc.exe") -and ($_.message -match "ImageLoaded.*.*ualapi.dll")) -and -not (($_.message -match "ImageLoaded.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
