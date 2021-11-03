# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\spoolsv.exe" -and $_.message -match "IntegrityLevel.*System" -and ($_.ID -eq "1") -and (((((($_.message -match "Image.*.*\\gpupdate.exe" -or $_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "Image.*.*\\nltest.exe" -or $_.message -match "Image.*.*\\taskkill.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\taskmgr.exe" -or $_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\findstr.exe" -or $_.message -match "Image.*.*\\curl.exe" -or $_.message -match "Image.*.*\\wget.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe" -or $_.message -match "Image.*.*\\accesschk.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\bcdedit.exe" -or $_.message -match "Image.*.*\\fsutil.exe" -or $_.message -match "Image.*.*\\cipher.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\write.exe" -or $_.message -match "Image.*.*\\wuauclt.exe") -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\net.exe" -and  -not ($_.message -match "CommandLine.*.*start"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\cmd.exe" -and  -not (($_.message -match "CommandLine.*.*.spl" -or $_.message -match "CommandLine.*.*route add" -or $_.message -match "CommandLine.*.*program files")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\netsh.exe" -and  -not (($_.message -match "CommandLine.*.*add portopening" -or $_.message -match "CommandLine.*.*rule name")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\powershell.exe" -and  -not ($_.message -match "CommandLine.*.*.spl"))) -or ($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*rundll32.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_spoolsv_child_processes";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_spoolsv_child_processes";
            $detectedMessage = "Detects suspicious print spool service (spoolsv.exe) child processes.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\spoolsv.exe" -and $_.message -match "IntegrityLevel.*System" -and ($_.ID -eq "1") -and (((((($_.message -match "Image.*.*\\gpupdate.exe" -or $_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "Image.*.*\\nltest.exe" -or $_.message -match "Image.*.*\\taskkill.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\taskmgr.exe" -or $_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\findstr.exe" -or $_.message -match "Image.*.*\\curl.exe" -or $_.message -match "Image.*.*\\wget.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe" -or $_.message -match "Image.*.*\\accesschk.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\bcdedit.exe" -or $_.message -match "Image.*.*\\fsutil.exe" -or $_.message -match "Image.*.*\\cipher.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\write.exe" -or $_.message -match "Image.*.*\\wuauclt.exe") -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\net.exe" -and -not ($_.message -match "CommandLine.*.*start"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\cmd.exe" -and -not (($_.message -match "CommandLine.*.*.spl" -or $_.message -match "CommandLine.*.*route add" -or $_.message -match "CommandLine.*.*program files")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\netsh.exe" -and -not (($_.message -match "CommandLine.*.*add portopening" -or $_.message -match "CommandLine.*.*rule name")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\powershell.exe" -and -not ($_.message -match "CommandLine.*.*.spl"))) -or ($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*rundll32.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
