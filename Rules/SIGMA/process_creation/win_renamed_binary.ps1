# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "cmd.exe" -or $_.message -match "powershell.exe" -or $_.message -match "powershell_ise.exe" -or $_.message -match "psexec.exe" -or $_.message -match "psexec.c" -or $_.message -match "cscript.exe" -or $_.message -match "wscript.exe" -or $_.message -match "mshta.exe" -or $_.message -match "regsvr32.exe" -or $_.message -match "wmic.exe" -or $_.message -match "certutil.exe" -or $_.message -match "rundll32.exe" -or $_.message -match "cmstp.exe" -or $_.message -match "msiexec.exe" -or $_.message -match "7z.exe" -or $_.message -match "winrar.exe" -or $_.message -match "wevtutil.exe" -or $_.message -match "net.exe" -or $_.message -match "net1.exe" -or $_.message -match "netsh.exe") -and  -not (($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe" -or $_.message -match "Image.*.*\\psexec.exe" -or $_.message -match "Image.*.*\\psexec64.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\cmstp.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\7z.exe" -or $_.message -match "Image.*.*\\winrar.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe" -or $_.message -match "Image.*.*\\netsh.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_binary";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_binary";
            $detectedMessage = "Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "cmd.exe" -or $_.message -match "powershell.exe" -or $_.message -match "powershell_ise.exe" -or $_.message -match "psexec.exe" -or $_.message -match "psexec.c" -or $_.message -match "cscript.exe" -or $_.message -match "wscript.exe" -or $_.message -match "mshta.exe" -or $_.message -match "regsvr32.exe" -or $_.message -match "wmic.exe" -or $_.message -match "certutil.exe" -or $_.message -match "rundll32.exe" -or $_.message -match "cmstp.exe" -or $_.message -match "msiexec.exe" -or $_.message -match "7z.exe" -or $_.message -match "winrar.exe" -or $_.message -match "wevtutil.exe" -or $_.message -match "net.exe" -or $_.message -match "net1.exe" -or $_.message -match "netsh.exe") -and -not (($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe" -or $_.message -match "Image.*.*\\psexec.exe" -or $_.message -match "Image.*.*\\psexec64.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\cmstp.exe" -or $_.message -match "Image.*.*\\msiexec.exe" -or $_.message -match "Image.*.*\\7z.exe" -or $_.message -match "Image.*.*\\winrar.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe" -or $_.message -match "Image.*.*\\netsh.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
