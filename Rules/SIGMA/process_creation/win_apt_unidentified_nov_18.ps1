# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*cyzfc.dat,.*" -and $_.message -match "CommandLine.*.*PointFunctionCall") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*ds7002.lnk.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_apt_unidentified_nov_18";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_apt_unidentified_nov_18";
            $detectedMessage = "A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with
YYTRIUM/APT29 campaign in 2016.";
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*cyzfc.dat,.*" -and $_.message -match "CommandLine.*.*PointFunctionCall") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*ds7002.lnk.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
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
