# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_sdelete";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_sdelete";
            $detectedMessage = "Detects renaming of file while deletion with SDelete tool.";
            $result = $event |  where { (($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
