# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_sdelete";
    $detectedMessage = "Detects renaming of file while deletion with SDelete tool.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4656" -or $_.ID -eq "4663" -or $_.ID -eq "4658") -and ($_.message -match "ObjectName.*.*.AAA" -or $_.message -match "ObjectName.*.*.ZZZ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}