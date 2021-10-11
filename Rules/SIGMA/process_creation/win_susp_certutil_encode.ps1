# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-f.*" -and $_.message -match "CommandLine.*.*-encode.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_certutil_encode";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_certutil_encode";
            $detectedMessage = "Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-f.*" -and $_.message -match "CommandLine.*.*-encode.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
