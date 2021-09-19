# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "ImageLoaded.*.*\Windows\System32\spool\drivers\x64\3\.*") -and ($_.message -match "ImageLoaded.*.*.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_spoolsv_dll_load";
    $detectedMessage = "Detect DLL Load from Spooler Service backup folder";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*spoolsv.exe") -and ($_.message -match "ImageLoaded.*.*\\Windows\\System32\\spool\\drivers\\x64\\3\\.*") -and ($_.message -match "ImageLoaded.*.*.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
