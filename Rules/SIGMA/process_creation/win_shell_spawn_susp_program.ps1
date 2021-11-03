# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\mshta.exe" -or $_.message -match "ParentImage.*.*\\powershell.exe" -or $_.message -match "ParentImage.*.*\\rundll32.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe" -or $_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\nslookup.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe" -or $_.message -match "Image.*.*\\mshta.exe")) -and  -not ($_.message -match "CurrentDirectory.*.*\\ccmcache\\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shell_spawn_susp_program";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_shell_spawn_susp_program";
            $detectedMessage = "Detects a suspicious child process of a Windows shell";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\mshta.exe" -or $_.message -match "ParentImage.*.*\\powershell.exe" -or $_.message -match "ParentImage.*.*\\rundll32.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe" -or $_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\wmiprvse.exe") -and ($_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\nslookup.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe" -or $_.message -match "Image.*.*\\mshta.exe")) -and -not ($_.message -match "CurrentDirectory.*.*\\ccmcache\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
