# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663") -and $_.message -match "ObjectType.*key" -and ($_.message -match "ObjectName.*.*lsa\JD" -or $_.message -match "ObjectName.*.*lsa\GBG" -or $_.message -match "ObjectName.*.*lsa\Skew1" -or $_.message -match "ObjectName.*.*lsa\Data")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_syskey_registry_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_syskey_registry_access";
            $detectedMessage = "Detects handle requests and access operations to specific registry keys to calculate the SysKey";
            $result = $event |  where { (($_.ID -eq "4656" -or $_.ID -eq "4663") -and $_.message -match "ObjectType.*key" -and ($_.message -match "ObjectName.*.*lsa\\JD" -or $_.message -match "ObjectName.*.*lsa\\GBG" -or $_.message -match "ObjectName.*.*lsa\\Skew1" -or $_.message -match "ObjectName.*.*lsa\\Data")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
