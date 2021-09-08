# Get-WinEvent -LogName System | where { ($_.ID -eq "7045" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "6" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Security | where { ($_.ID -eq "4697" -and ($_.Service File Name -eq "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message


function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_powershell_script_installed_as_service";
    $detectedMessage = "Detects powershell script installed as a Service";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "7045" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "6" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "4697" -and ($_.message -match "*powershell*" -or $_.message -match "Service File Name.*.*pwsh.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
