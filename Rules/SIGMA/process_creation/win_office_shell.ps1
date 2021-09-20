# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe" -or $_.message -match "ParentImage.*.*\\OUTLOOK.EXE" -or $_.message -match "ParentImage.*.*\\MSACCESS.EXE" -or $_.message -match "ParentImage.*.*\\EQNEDT32.EXE") -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\scrcons.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\hh.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\forfiles.exe" -or $_.message -match "Image.*.*\\scriptrunner.exe" -or $_.message -match "Image.*.*\\mftrace.exe" -or $_.message -match "Image.*.*\\AppVLP.exe" -or $_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\msbuild.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_office_shell";
    $detectedMessage = "Detects a Windows command and scripting interpreter executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe" -or $_.message -match "ParentImage.*.*\\OUTLOOK.EXE" -or $_.message -match "ParentImage.*.*\\MSACCESS.EXE" -or $_.message -match "ParentImage.*.*\\EQNEDT32.EXE") -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\scrcons.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\hh.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\forfiles.exe" -or $_.message -match "Image.*.*\\scriptrunner.exe" -or $_.message -match "Image.*.*\\mftrace.exe" -or $_.message -match "Image.*.*\\AppVLP.exe" -or $_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\msbuild.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
