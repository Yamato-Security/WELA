# Get-WinEvent -LogName Security | where {(($_.ID -eq "4742" -and $_.message -match "SubjectUserName.*ANONYMOUS LOGON" -and $_.message -match "TargetUserName.*%DC-MACHINE-NAME%") -and  -not ($_.message -match "PasswordLastSet.*-")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_privesc_cve_2020_1472";
    $detectedMessage = "Detects Netlogon Elevation of Privilege Vulnerability aka Zerologon (CVE-2020-1472)";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4742" -and $_.message -match "SubjectUserName.*ANONYMOUS LOGON" -and $_.message -match "TargetUserName.*%DC-MACHINE-NAME%") -and -not ($_.message -match "PasswordLastSet.*-")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
