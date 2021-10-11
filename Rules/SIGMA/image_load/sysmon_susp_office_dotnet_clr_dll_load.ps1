# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\winword.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\clr.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_office_dotnet_clr_dll_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_office_dotnet_clr_dll_load";
            $detectedMessage = "Detects CLR DLL being loaded by an Office Product";
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\excel.exe" -or $_.message -match "Image.*.*\\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\\clr.dll.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
