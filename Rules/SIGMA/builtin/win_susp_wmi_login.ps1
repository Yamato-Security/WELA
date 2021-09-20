# Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "ProcessName.*.*\WmiPrvSE.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wmi_login";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_wmi_login";
            $detectedMessage = "Detection of logins performed with WMI";
            $result = $event |  where { ($_.ID -eq "4624" -and $_.message -match "ProcessName.*.*\\WmiPrvSE.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
