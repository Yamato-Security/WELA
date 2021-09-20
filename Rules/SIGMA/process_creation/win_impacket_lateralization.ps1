# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.ID -eq "1" -and $_.message -match "CommandLine.*.*cmd.exe.*" -and $_.message -match "CommandLine.*.*&1.*" -and ((($_.message -match "ParentImage.*.*\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\mmc.exe" -or $_.message -match "ParentImage.*.*\explorer.exe" -or $_.message -match "ParentImage.*.*\services.exe") -and $_.message -match "CommandLine.*.*/Q.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*\\127.0.0.1\.*") -or (($_.message -match "ParentCommandLine.*.*svchost.exe -k netsvcs.*" -or $_.message -match "ParentCommandLine.*.*taskeng.exe.*") -and $_.message -match "CommandLine.*.*/C.*" -and $_.message -match "CommandLine.*.*Windows\Temp\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_impacket_lateralization";
    $detectedMessage = "Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and $_.ID -eq "1" -and $_.message -match "CommandLine.*.*cmd.exe.*" -and $_.message -match "CommandLine.*.*&1.*" -and ((($_.message -match "ParentImage.*.*\\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\\mmc.exe" -or $_.message -match "ParentImage.*.*\\explorer.exe" -or $_.message -match "ParentImage.*.*\\services.exe") -and $_.message -match "CommandLine.*.*/Q.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*\\\\127.0.0.1\\.*") -or (($_.message -match "ParentCommandLine.*.*svchost.exe -k netsvcs.*" -or $_.message -match "ParentCommandLine.*.*taskeng.exe.*") -and $_.message -match "CommandLine.*.*/C.*" -and $_.message -match "CommandLine.*.*Windows\\Temp\\.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
