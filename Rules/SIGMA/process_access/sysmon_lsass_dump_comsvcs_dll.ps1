# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "SourceImage.*C:\Windows\System32\rundll32.exe" -and $_.message -match "CallTrace.*.*comsvcs.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_lsass_dump_comsvcs_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_lsass_dump_comsvcs_dll";
            $detectedMessage = "Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.";
            $result = $event |  where { ($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\lsass.exe" -and $_.message -match "SourceImage.*C:\\Windows\\System32\\rundll32.exe" -and $_.message -match "CallTrace.*.*comsvcs.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
