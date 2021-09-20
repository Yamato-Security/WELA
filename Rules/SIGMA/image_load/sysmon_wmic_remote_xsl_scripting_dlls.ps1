# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\jscript.dll" -or $_.message -match "ImageLoaded.*.*\vbscript.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmic_remote_xsl_scripting_dlls";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_wmic_remote_xsl_scripting_dlls";
                $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\\jscript.dll" -or $_.message -match "ImageLoaded.*.*\\vbscript.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
