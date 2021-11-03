# Get-WinEvent -LogName Security | where {($_.ID -eq "4720" -and $_.message -match "SamAccountName.*.*ANONYMOUS" -and $_.message -match "SamAccountName.*.*LOGON") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_local_anon_logon_created";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_local_anon_logon_created";
            $detectedMessage = "Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.";
            $result = $event |  where { ($_.ID -eq "4720" -and $_.message -match "SamAccountName.*.*ANONYMOUS" -and $_.message -match "SamAccountName.*.*LOGON") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
