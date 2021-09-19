# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*objectcategory.*" -or $_.message -match "CommandLine.*.*trustdmp.*" -or $_.message -match "CommandLine.*.*dcmodes.*" -or $_.message -match "CommandLine.*.*dclist.*" -or $_.message -match "CommandLine.*.*computers_pwdnotreqd.*") -and $_.message -match "Image.*.*\adfind.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_adfind";
    $detectedMessage = "Detects the execution of a AdFind for Active Directory enumeration ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*objectcategory.*" -or $_.message -match "CommandLine.*.*trustdmp.*" -or $_.message -match "CommandLine.*.*dcmodes.*" -or $_.message -match "CommandLine.*.*dclist.*" -or $_.message -match "CommandLine.*.*computers_pwdnotreqd.*") -and $_.message -match "Image.*.*\adfind.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
