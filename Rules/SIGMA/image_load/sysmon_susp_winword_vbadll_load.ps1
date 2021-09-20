# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\winword.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\VBE7.DLL" -or $_.message -match "ImageLoaded.*.*\VBEUI.DLL" -or $_.message -match "ImageLoaded.*.*\VBE7INTL.DLL")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_winword_vbadll_load";
    $detectedMessage = "Detects DLL's Loaded Via Word Containing VBA Macros";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\excel.exe" -or $_.message -match "Image.*.*\\outlook.exe") -and ($_.message -match "ImageLoaded.*.*\\VBE7.DLL" -or $_.message -match "ImageLoaded.*.*\\VBEUI.DLL" -or $_.message -match "ImageLoaded.*.*\\VBE7INTL.DLL")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
