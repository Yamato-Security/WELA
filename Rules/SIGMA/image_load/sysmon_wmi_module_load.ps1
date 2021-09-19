# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\wmiclnt.dll" -or $_.message -match "ImageLoaded.*.*\WmiApRpl.dll" -or $_.message -match "ImageLoaded.*.*\wmiprov.dll" -or $_.message -match "ImageLoaded.*.*\wmiutils.dll" -or $_.message -match "ImageLoaded.*.*\wbemcomn.dll" -or $_.message -match "ImageLoaded.*.*\wbemprox.dll" -or $_.message -match "ImageLoaded.*.*\WMINet_Utils.dll" -or $_.message -match "ImageLoaded.*.*\wbemsvc.dll" -or $_.message -match "ImageLoaded.*.*\fastprox.dll") -and  -not (($_.message -match "Image.*.*\WmiPrvSE.exe" -or $_.message -match "Image.*.*\WmiApSrv.exe" -or $_.message -match "Image.*.*\svchost.exe" -or $_.message -match "Image.*.*\DeviceCensus.exe" -or $_.message -match "Image.*.*\CompatTelRunner.exe" -or $_.message -match "Image.*.*\sdiagnhost.exe" -or $_.message -match "Image.*.*\SIHClient.exe" -or $_.message -match "Image.*.*\ngentask.exe" -or $_.message -match "Image.*.*\windows\system32\taskhostw.exe" -or $_.message -match "Image.*.*\windows\system32\MoUsoCoreWorker.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmi_module_load";
    $detectedMessage = "Detects non wmiprvse loading WMI modules";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\\wmiclnt.dll" -or $_.message -match "ImageLoaded.*.*\\WmiApRpl.dll" -or $_.message -match "ImageLoaded.*.*\\wmiprov.dll" -or $_.message -match "ImageLoaded.*.*\\wmiutils.dll" -or $_.message -match "ImageLoaded.*.*\\wbemcomn.dll" -or $_.message -match "ImageLoaded.*.*\\wbemprox.dll" -or $_.message -match "ImageLoaded.*.*\\WMINet_Utils.dll" -or $_.message -match "ImageLoaded.*.*\\wbemsvc.dll" -or $_.message -match "ImageLoaded.*.*\\fastprox.dll") -and -not (($_.message -match "Image.*.*\\WmiPrvSE.exe" -or $_.message -match "Image.*.*\\WmiApSrv.exe" -or $_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\DeviceCensus.exe" -or $_.message -match "Image.*.*\\CompatTelRunner.exe" -or $_.message -match "Image.*.*\\sdiagnhost.exe" -or $_.message -match "Image.*.*\\SIHClient.exe" -or $_.message -match "Image.*.*\\ngentask.exe" -or $_.message -match "Image.*.*\\windows\\system32\\taskhostw.exe" -or $_.message -match "Image.*.*\\windows\\system32\\MoUsoCoreWorker.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
