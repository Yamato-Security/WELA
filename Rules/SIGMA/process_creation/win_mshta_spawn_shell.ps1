# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\mshta.exe" -and (($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\reg.exe" -or $_.message -match "Image.*.*\regsvr32.exe") -or ($_.message -match "Image.*.*\BITSADMIN.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mshta_spawn_shell";
    $detectedMessage = "Detects a Windows command line executable started from MSHTA";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\mshta.exe" -and (($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\reg.exe" -or $_.message -match "Image.*.*\\regsvr32.exe") -or ($_.message -match "Image.*.*\\BITSADMIN.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
