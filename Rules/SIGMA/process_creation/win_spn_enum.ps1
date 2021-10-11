# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\setspn.exe" -or ($_.message -match "Description.*.*Query or reset the computer.*" -and $_.message -match "Description.*.*SPN attribute.*")) -and $_.message -match "CommandLine.*.*-q.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_spn_enum";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_spn_enum";
            $detectedMessage = "Detects Service Principal Name Enumeration used for Kerberoasting";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\setspn.exe" -or ($_.message -match "Description.*.*Query or reset the computer.*" -and $_.message -match "Description.*.*SPN attribute.*")) -and $_.message -match "CommandLine.*.*-q.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
