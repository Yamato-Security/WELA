# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "DestinationPort.*88" -and $_.message -match "Initiated.*true") -and  -not (($_.message -match "Image.*.*\lsass.exe" -or $_.message -match "Image.*.*\opera.exe" -or $_.message -match "Image.*.*\chrome.exe" -or $_.message -match "Image.*.*\firefox.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_suspicious_outbound_kerberos_connection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_suspicious_outbound_kerberos_connection";
            $detectedMessage = "Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.";
            $result = $event |  where { (($_.ID -eq "3") -and ($_.message -match "DestinationPort.*88" -and $_.message -match "Initiated.*true") -and -not (($_.message -match "Image.*.*\\lsass.exe" -or $_.message -match "Image.*.*\\opera.exe" -or $_.message -match "Image.*.*\\chrome.exe" -or $_.message -match "Image.*.*\\firefox.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
