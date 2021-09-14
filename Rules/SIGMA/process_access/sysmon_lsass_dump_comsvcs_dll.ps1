# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "SourceImage.*C:\Windows\System32\rundll32.exe" -and $_.message -match "CallTrace.*.*comsvcs.dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_lsass_dump_comsvcs_dll";
    $detectedMessage = "Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "SourceImage.*C:\Windows\System32\rundll32.exe" -and $_.message -match "CallTrace.*.*comsvcs.dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
