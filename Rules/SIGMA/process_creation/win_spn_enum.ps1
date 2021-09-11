# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\setspn.exe" -or ($_.message -match "Description.*.*Query or reset the computer.*" -and $_.message -match "Description.*.*SPN attribute.*")) -and $_.message -match "CommandLine.*.*-q.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_spn_enum";
    $detectedMessage = "Detects Service Principal Name Enumeration used for Kerberoasting";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\setspn.exe" -or ($_.message -match "Description.*.*Query or reset the computer.*" -and $_.message -match "Description.*.*SPN attribute.*")) -and $_.message -match "CommandLine.*.*-q.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
