# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\excel.exe") -and $_.message -match "CommandLine.*.*http") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_msoffice";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_msoffice";
            $detectedMessage = "Downloads payload from remote server";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\excel.exe") -and $_.message -match "CommandLine.*.*http") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
