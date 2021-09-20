# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*dll,MyStart.*" -or $_.message -match "CommandLine.*.*dll MyStart.*") -or ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* MyStart") -and ($_.message -match "CommandLine.*.*rundll32.exe.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_taidoor";
    $detectedMessage = "Detects specific process characteristics of Chinese TAIDOOR RAT malware load";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*dll,MyStart.*" -or $_.message -match "CommandLine.*.*dll MyStart.*") -or ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* MyStart") -and ($_.message -match "CommandLine.*.*rundll32.exe.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
