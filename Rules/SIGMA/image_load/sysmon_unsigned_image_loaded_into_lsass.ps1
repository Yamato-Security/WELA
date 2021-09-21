# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\lsass.exe" -and $_.message -match "Signed.*false") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_unsigned_image_loaded_into_lsass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_unsigned_image_loaded_into_lsass";
            $detectedMessage = "Loading unsigned image (DLL, EXE) into LSASS process";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\\lsass.exe" -and $_.message -match "Signed.*false") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
