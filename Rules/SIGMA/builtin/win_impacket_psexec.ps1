# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "RelativeTargetName.*.*RemCom_stdint.*" -or $_.message -match "RelativeTargetName.*.*RemCom_stdoutt.*" -or $_.message -match "RelativeTargetName.*.*RemCom_stderrt.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_impacket_psexec";
    $detectedMessage = "Detects execution of Impacket's psexec.py.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "RelativeTargetName.*.*RemCom_stdint.*" -or $_.message -match "RelativeTargetName.*.*RemCom_stdoutt.*" -or $_.message -match "RelativeTargetName.*.*RemCom_stderrt.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
