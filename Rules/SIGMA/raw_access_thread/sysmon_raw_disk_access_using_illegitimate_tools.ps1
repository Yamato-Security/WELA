# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "9") -and  -not ($_.message -match "Device.*.*floppy.*") -and  -not (($_.message -match "Image.*.*\wmiprvse.exe" -or $_.message -match "Image.*.*\sdiagnhost.exe" -or $_.message -match "Image.*.*\searchindexer.exe" -or $_.message -match "Image.*.*\csrss.exe" -or $_.message -match "Image.*.*\defrag.exe" -or $_.message -match "Image.*.*\smss.exe" -or $_.message -match "Image.*.*\vssvc.exe" -or $_.message -match "Image.*.*\compattelrunner.exe" -or $_.message -match "Image.*.*\wininit.exe" -or $_.message -match "Image.*.*\autochk.exe" -or $_.message -match "Image.*.*\taskhost.exe" -or $_.message -match "Image.*.*\dfsrs.exe" -or $_.message -match "Image.*.*\vds.exe" -or $_.message -match "Image.*.*\lsass.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_raw_disk_access_using_illegitimate_tools";
    $detectedMessage = "Raw disk access using illegitimate tools, possible defence evasion";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "9") -and -not ($_.message -match "Device.*.*floppy.*") -and -not (($_.message -match "Image.*.*\wmiprvse.exe" -or $_.message -match "Image.*.*\sdiagnhost.exe" -or $_.message -match "Image.*.*\searchindexer.exe" -or $_.message -match "Image.*.*\csrss.exe" -or $_.message -match "Image.*.*\defrag.exe" -or $_.message -match "Image.*.*\smss.exe" -or $_.message -match "Image.*.*\vssvc.exe" -or $_.message -match "Image.*.*\compattelrunner.exe" -or $_.message -match "Image.*.*\wininit.exe" -or $_.message -match "Image.*.*\autochk.exe" -or $_.message -match "Image.*.*\taskhost.exe" -or $_.message -match "Image.*.*\dfsrs.exe" -or $_.message -match "Image.*.*\vds.exe" -or $_.message -match "Image.*.*\lsass.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0]0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
