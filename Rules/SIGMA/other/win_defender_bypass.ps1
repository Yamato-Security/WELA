# Get-WinEvent -LogName Security | where {(($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\Microsoft\Windows Defender\Exclusions\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_bypass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_defender_bypass";
            $detectedMessage = "'Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender'";
            $result = $event |  where { (($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\\Microsoft\\Windows Defender\\Exclusions\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
