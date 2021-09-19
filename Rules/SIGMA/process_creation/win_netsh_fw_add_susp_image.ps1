# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*firewall.*" -and $_.message -match "CommandLine.*.*add.*" -and ($_.message -match "CommandLine.*.*allowedprogram.*" -or ($_.message -match "CommandLine.*.*advfirewall.*" -and $_.message -match "CommandLine.*.*rule.*" -and $_.message -match "CommandLine.*.*action=allow.*" -and $_.message -match "CommandLine.*.*program=.*"))) -and (($_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*:\RECYCLER\.*" -or $_.message -match "CommandLine.*.*C:\$Recycle.bin\.*" -or $_.message -match "CommandLine.*.*:\SystemVolumeInformation\.*" -or $_.message -match "CommandLine.*.*C:\Windows\Temp\.*" -or $_.message -match "CommandLine.*.*C:\Temp\.*" -or $_.message -match "CommandLine.*.*C:\Users\Public\.*" -or $_.message -match "CommandLine.*.*C:\Users\Default\.*" -or $_.message -match "CommandLine.*.*C:\Users\Desktop\.*" -or $_.message -match "CommandLine.*.*\Downloads\.*" -or $_.message -match "CommandLine.*.*\Temporary Internet Files\Content.Outlook\.*" -or $_.message -match "CommandLine.*.*\Local Settings\Temporary Internet Files\.*") -or ($_.message -match "CommandLine.*C:\Windows\Tasks\.*" -or $_.message -match "CommandLine.*C:\Windows\debug\.*" -or $_.message -match "CommandLine.*C:\Windows\fonts\.*" -or $_.message -match "CommandLine.*C:\Windows\help\.*" -or $_.message -match "CommandLine.*C:\Windows\drivers\.*" -or $_.message -match "CommandLine.*C:\Windows\addins\.*" -or $_.message -match "CommandLine.*C:\Windows\cursors\.*" -or $_.message -match "CommandLine.*C:\Windows\system32\tasks\.*" -or $_.message -match "CommandLine.*%Public%\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_netsh_fw_add_susp_image";
    $detectedMessage = "Detects Netsh commands that allows a suspcious application location on Windows Firewall";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*firewall.*" -and $_.message -match "CommandLine.*.*add.*" -and ($_.message -match "CommandLine.*.*allowedprogram.*" -or ($_.message -match "CommandLine.*.*advfirewall.*" -and $_.message -match "CommandLine.*.*rule.*" -and $_.message -match "CommandLine.*.*action=allow.*" -and $_.message -match "CommandLine.*.*program=.*"))) -and (($_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*:\RECYCLER\.*" -or $_.message -match "CommandLine.*.*C:\$Recycle.bin\.*" -or $_.message -match "CommandLine.*.*:\SystemVolumeInformation\.*" -or $_.message -match "CommandLine.*.*C:\Windows\Temp\.*" -or $_.message -match "CommandLine.*.*C:\Temp\.*" -or $_.message -match "CommandLine.*.*C:\Users\Public\.*" -or $_.message -match "CommandLine.*.*C:\Users\Default\.*" -or $_.message -match "CommandLine.*.*C:\Users\Desktop\.*" -or $_.message -match "CommandLine.*.*\Downloads\.*" -or $_.message -match "CommandLine.*.*\Temporary Internet Files\Content.Outlook\.*" -or $_.message -match "CommandLine.*.*\Local Settings\Temporary Internet Files\.*") -or ($_.message -match "CommandLine.*C:\Windows\Tasks\.*" -or $_.message -match "CommandLine.*C:\Windows\debug\.*" -or $_.message -match "CommandLine.*C:\Windows\fonts\.*" -or $_.message -match "CommandLine.*C:\Windows\help\.*" -or $_.message -match "CommandLine.*C:\Windows\drivers\.*" -or $_.message -match "CommandLine.*C:\Windows\addins\.*" -or $_.message -match "CommandLine.*C:\Windows\cursors\.*" -or $_.message -match "CommandLine.*C:\Windows\system32\tasks\.*" -or $_.message -match "CommandLine.*%Public%\.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
