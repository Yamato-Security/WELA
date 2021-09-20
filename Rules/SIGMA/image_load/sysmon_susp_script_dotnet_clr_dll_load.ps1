# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\mshta.exe") -and ($_.message -match "ImageLoaded.*.*\clr.dll" -or $_.message -match "ImageLoaded.*.*\mscoree.dll" -or $_.message -match "ImageLoaded.*.*\mscorlib.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_script_dotnet_clr_dll_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_susp_script_dotnet_clr_dll_load";
                    $detectedMessage = "Detects CLR DLL being loaded by an scripting applications";
                $result = $event |  where { ($_.ID -eq "7" -and ($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\mshta.exe") -and ($_.message -match "ImageLoaded.*.*\\clr.dll" -or $_.message -match "ImageLoaded.*.*\\mscoree.dll" -or $_.message -match "ImageLoaded.*.*\\mscorlib.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
