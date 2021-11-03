# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "ImageLoaded.*.*\Windows\System32\spool\drivers\x64\3\") -and ($_.message -match "ImageLoaded.*.*.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_spoolsv_dll_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_spoolsv_dll_load";
            $detectedMessage = "Detect DLL Load from Spooler Service backup folder";
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "ImageLoaded.*.*\\Windows\\System32\\spool\\drivers\\x64\\3\\") -and ($_.message -match "ImageLoaded.*.*.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
