# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "powershell.exe" -or $_.message -match "powershell_ise.exe" -or $_.message -match "psexec.exe" -or $_.message -match "psexec.c" -or $_.message -match "cscript.exe" -or $_.message -match "wscript.exe" -or $_.message -match "mshta.exe" -or $_.message -match "regsvr32.exe" -or $_.message -match "wmic.exe" -or $_.message -match "certutil.exe" -or $_.message -match "rundll32.exe" -or $_.message -match "cmstp.exe" -or $_.message -match "msiexec.exe") -and  -not (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\powershell_ise.exe" -or $_.message -match "Image.*.*\psexec.exe" -or $_.message -match "Image.*.*\psexec64.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\certutil.exe" -or $_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\cmstp.exe" -or $_.message -match "Image.*.*\msiexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_renamed_binary_highly_relevant";
    $detectedMessage = "Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "powershell.exe" -or $_.message -match "powershell_ise.exe" -or $_.message -match "psexec.exe" -or $_.message -match "psexec.c" -or $_.message -match "cscript.exe" -or $_.message -match "wscript.exe" -or $_.message -match "mshta.exe" -or $_.message -match "regsvr32.exe" -or $_.message -match "wmic.exe" -or $_.message -match "certutil.exe" -or $_.message -match "rundll32.exe" -or $_.message -match "cmstp.exe" -or $_.message -match "msiexec.exe") -and -not (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\powershell_ise.exe" -or $_.message -match "Image.*.*\psexec.exe" -or $_.message -match "Image.*.*\psexec64.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\certutil.exe" -or $_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\cmstp.exe" -or $_.message -match "Image.*.*\msiexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}