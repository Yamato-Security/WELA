# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*/q.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*chcp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_koadic";
    $detectedMessage = "Detects command line parameters used by Koadic hack tool";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*/q.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*chcp.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
