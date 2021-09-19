# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\ntdsutil.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ntdsutil";
    $detectedMessage = "Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\ntdsutil.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
