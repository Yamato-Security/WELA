# Get-WinEvent -LogName System | where { ($_.ID -eq "7045" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "6" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Security | where { ($_.ID -eq "4697" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message


function Add-Rule {

    $ruleName = "win_powershell_script_installed_as_service";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_script_installed_as_service";
            $detectedMessage = "Detects powershell script installed as a Service"
            $results = @();
            $results += $event | where { ($_.ID -eq "7045" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "6" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "4697" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
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
