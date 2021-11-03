# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\winword.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\dsparse.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_office_dsparse_dll_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_office_dsparse_dll_load";
            $detectedMessage = "Detects DSParse DLL being loaded by an Office Product";
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\excel.exe" -or $_.message -match "Image.*.*\\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\\dsparse.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
