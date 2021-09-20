# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmstp.exe" -and ($_.message -match "CommandLine.*.*/s.*" -or $_.message -match "CommandLine.*.*/au.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_uac_cmstp";
    $detectedMessage = "Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmstp.exe" -and ($_.message -match "CommandLine.*.*/s.*" -or $_.message -match "CommandLine.*.*/au.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
