# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.* --adcs .*" -and $_.message -match "CommandLine.*.* --port .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_adcspwn";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hack_adcspwn";
            $detectedMessage = "Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.* --adcs .*" -and $_.message -match "CommandLine.*.* --port .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
