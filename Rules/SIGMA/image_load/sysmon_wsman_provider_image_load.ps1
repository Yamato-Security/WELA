# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ((($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\WsmSvc.dll" -or $_.message -match "ImageLoaded.*.*\WsmAuto.dll" -or $_.message -match "ImageLoaded.*.*\Microsoft.WSMan.Management.ni.dll") -or ($_.message -match "WsmSvc.dll" -or $_.message -match "WSMANAUTOMATION.DLL" -or $_.message -match "Microsoft.WSMan.Management.dll")) -and  -not ($_.message -match "Image.*.*\powershell.exe")) -or ($_.message -match "Image.*.*\svchost.exe" -and $_.message -match "OriginalFileName.*WsmWmiPl.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wsman_provider_image_load";
    $detectedMessage = "Detects signs of potential use of the WSMAN provider from uncommon processes locally and remote execution.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "7") -and ((($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\\WsmSvc.dll" -or $_.message -match "ImageLoaded.*.*\\WsmAuto.dll" -or $_.message -match "ImageLoaded.*.*\\Microsoft.WSMan.Management.ni.dll") -or ($_.message -match "WsmSvc.dll" -or $_.message -match "WSMANAUTOMATION.DLL" -or $_.message -match "Microsoft.WSMan.Management.dll")) -and -not ($_.message -match "Image.*.*\\powershell.exe")) -or ($_.message -match "Image.*.*\\svchost.exe" -and $_.message -match "OriginalFileName.*WsmWmiPl.dll"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
