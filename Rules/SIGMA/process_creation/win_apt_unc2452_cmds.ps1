# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((((($_.message -match "CommandLine.*.*7z.exe a -v500m -mx9 -r0 -p") -or ($_.message -match "ParentCommandLine.*.*wscript.exe" -and $_.message -match "ParentCommandLine.*.*.vbs" -and $_.message -match "CommandLine.*.*rundll32.exe" -and $_.message -match "CommandLine.*.*C:\Windows" -and $_.message -match "CommandLine.*.*.dll,Tk_")) -or ($_.message -match "ParentImage.*.*\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*C:\Windows" -and $_.message -match "CommandLine.*.*cmd.exe /C ")) -or ($_.message -match "CommandLine.*.*rundll32 c:\windows\" -and $_.message -match "CommandLine.*.*.dll ")) -or (($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\rundll32.exe" -and $_.message -match "Image.*.*\dllhost.exe") -and  -not (($_.message -match " " -or $_.message -match ""))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_unc2452_cmds";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_unc2452_cmds";
            $detectedMessage = "Detects a specific process creation patterns as seen used by UNC2452 and provided by Microsoft as Microsoft Defender ATP queries";
            $result = $event | where { (($_.ID -eq "1") -and ((((($_.message -match "CommandLine.*.*7z.exe a -v500m -mx9 -r0 -p") -or ($_.message -match "ParentCommandLine.*.*wscript.exe" -and $_.message -match "ParentCommandLine.*.*.vbs" -and $_.message -match "CommandLine.*.*rundll32.exe" -and $_.message -match "CommandLine.*.*C:\\Windows" -and $_.message -match "CommandLine.*.*.dll,Tk_")) -or ($_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*C:\\Windows" -and $_.message -match "CommandLine.*.*cmd.exe /C ")) -or ($_.message -match "CommandLine.*.*rundll32 c:\\windows\\" -and $_.message -match "CommandLine.*.*.dll ")) -or (($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "Image.*.*\\dllhost.exe") -and -not (($_.message -match " " -or $_.message -match ""))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
