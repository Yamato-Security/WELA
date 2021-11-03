# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\vss_ps.dll") -and  -not (($_.message -match "Image.*.*\svchost.exe" -or $_.message -match "Image.*.*\msiexec.exe" -or $_.message -match "Image.*.*\vssvc.exe" -or $_.message -match "Image.*.*\srtasks.exe" -or $_.message -match "Image.*.*\tiworker.exe" -or $_.message -match "Image.*.*\dllhost.exe" -or $_.message -match "Image.*.*\searchindexer.exe" -or $_.message -match "Image.*.*dismhost.exe" -or $_.message -match "Image.*.*taskhostw.exe" -or $_.message -match "Image.*.*\clussvc.exe") -and $_.message -match "Image.*.*c:\windows\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_suspicious_vss_ps_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_suspicious_vss_ps_load";
            $detectedMessage = "Detects the image load of vss_ps.dll by uncommon executables using OriginalFileName datapoint";
            $result = $event |  where { (($_.ID -eq "7") -and ($_.message -match "ImageLoaded.*.*\\vss_ps.dll") -and -not (($_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\vssvc.exe" -or $_.message -match "Image.*.*\\srtasks.exe" -or $_.message -match "Image.*.*\\tiworker.exe" -or $_.message -match "Image.*.*\\dllhost.exe" -or $_.message -match "Image.*.*\\searchindexer.exe" -or $_.message -match "Image.*.*dismhost.exe" -or $_.message -match "Image.*.*taskhostw.exe" -or $_.message -match "Image.*.*\\clussvc.exe") -and $_.message -match "Image.*.*c:\\windows\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
