# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and (($_.message -match "Image.*.*fxssvc.exe") -and ($_.message -match "ImageLoaded.*.*ualapi.dll")) -and  -not (($_.message -match "ImageLoaded.*C:\Windows\WinSxS\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_fax_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_fax_dll";
            $detectedMessage = "The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.";
            $result = $event |  where { (($_.ID -eq "7") -and (($_.message -match "Image.*.*fxssvc.exe") -and ($_.message -match "ImageLoaded.*.*ualapi.dll")) -and -not (($_.message -match "ImageLoaded.*C:\\Windows\\WinSxS\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
