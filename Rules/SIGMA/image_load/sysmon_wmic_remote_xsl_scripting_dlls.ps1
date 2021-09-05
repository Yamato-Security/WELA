# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\jscript.dll" -or $_.message -match "ImageLoaded.*.*\vbscript.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_wmic_remote_xsl_scripting_dlls";
    $detectedMessage = "Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\jscript.dll" -or $_.message -match "ImageLoaded.*.*\vbscript.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
