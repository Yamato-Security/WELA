# Get-WinEvent -LogName Security | where {($_.ID -eq "4663" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\Device\CdRom") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_iso_mount";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_iso_mount";
            $detectedMessage = "Detects the mount of ISO images on an endpoint";
            $result = $event |  where { ($_.ID -eq "4663" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\\Device\\CdRom") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
