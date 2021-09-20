# Get-WinEvent -LogName System | where {($_.ID -eq "16" -and $_.message -match ".*\AppData\Local\Temp\SAM-.*" -and $_.message -match ".*.dmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_sam_dump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_sam_dump";
            $detectedMessage = "Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers";
            $result = $event |  where { ($_.ID -eq "16" -and $_.message -match ".*\\AppData\\Local\\Temp\\SAM-.*" -and $_.message -match ".*.dmp.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
