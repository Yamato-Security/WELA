# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\System.Management.Automation.Dll" -or $_.message -match "ImageLoaded.*.*\System.Management.Automation.ni.Dll") -and  -not (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\powershell_ise.exe" -or $_.message -match "Image.*.*\WINDOWS\System32\sdiagnhost.exe" -or $_.message -match "Image.*.*\mscorsvw.exe" -or $_.message -match "Image.*.*\WINDOWS\System32\RemoteFXvGPUDisablement.exe" -or $_.message -match "Image.*.*\sqlps.exe" -or $_.message -match "Image.*.*\wsmprovhost.exe" -or $_.message -match "Image.*.*\winrshost.exe" -or $_.message -match "Image.*.*\syncappvpublishingserver.exe" -or $_.message -match "Image.*.*\runscripthelper.exe" -or $_.message -match "Image.*.*\ServerManager.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_in_memory_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_in_memory_powershell";
            $detectedMessage = "Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's ""load powershell"" extension.";
            $result = $event |  where { (($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\\System.Management.Automation.Dll" -or $_.message -match "ImageLoaded.*.*\\System.Management.Automation.ni.Dll") -and -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe" -or $_.message -match "Image.*.*\\WINDOWS\\System32\\sdiagnhost.exe" -or $_.message -match "Image.*.*\\mscorsvw.exe" -or $_.message -match "Image.*.*\\WINDOWS\\System32\\RemoteFXvGPUDisablement.exe" -or $_.message -match "Image.*.*\\sqlps.exe" -or $_.message -match "Image.*.*\\wsmprovhost.exe" -or $_.message -match "Image.*.*\\winrshost.exe" -or $_.message -match "Image.*.*\\syncappvpublishingserver.exe" -or $_.message -match "Image.*.*\\runscripthelper.exe" -or $_.message -match "Image.*.*\\ServerManager.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
