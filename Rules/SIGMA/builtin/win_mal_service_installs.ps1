# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.Service File Name -eq "*\\PAExec*" -or $_.message -match "ServiceName.*mssecsvc2.0" -or $_.Service File Name -eq "*net user*" -or $_.message -match "ServiceName.*Java(TM) Virtual Machine Support Service")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and $_.message -match "ServiceName.*javamtsup") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mal_service_installs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "7045" -and ($_.message -match "\\PAExec*" -or $_.message -match "ServiceName.*mssecsvc2.0" -or $_.message -match "net user*" -or $_.message -match "ServiceName.*Java(TM) Virtual Machine Support Service")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp)
            $tmp = $event | where { ($_.ID -eq "4697" -and $_.message -match "ServiceName.*javamtsup") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp)
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
            }            
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
