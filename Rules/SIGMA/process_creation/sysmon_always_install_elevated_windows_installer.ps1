# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "User.*NT AUTHORITY\SYSTEM" -and (($_.message -match "Image.*.*\Windows\Installer\" -and $_.message -match "Image.*.*msi" -and ($_.message -match "Image.*.*tmp")) -or (($_.message -match "Image.*.*\msiexec.exe") -and $_.message -match "IntegrityLevel.*System"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_always_install_elevated_windows_installer";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_always_install_elevated_windows_installer";
            $detectedMessage = "This rule will looks for Windows Installer service (msiexec.exe) when it tries to install MSI packages with SYSTEM privilege ";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM" -and (($_.message -match "Image.*.*\\Windows\\Installer\\" -and $_.message -match "Image.*.*msi" -and ($_.message -match "Image.*.*tmp")) -or (($_.message -match "Image.*.*\\msiexec.exe") -and $_.message -match "IntegrityLevel.*System"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
