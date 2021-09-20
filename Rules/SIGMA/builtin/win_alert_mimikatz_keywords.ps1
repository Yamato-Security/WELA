# Get-WinEvent | where {($_.message -match ".*mimikatz.*" -or $_.message -match ".*mimilib.*" -or $_.message -match ".*<3 eo.oe.*" -or $_.message -match ".*eo.oe.kiwi.*" -or $_.message -match ".*privilege::debug.*" -or $_.message -match ".*sekurlsa::logonpasswords.*" -or $_.message -match ".*lsadump::sam.*" -or $_.message -match ".*mimidrv.sys.*" -or $_.message -match ".* p::d .*" -or $_.message -match ".* s::l .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_mimikatz_keywords";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_mimikatz_keywords";
            $detectedMessage = "This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)";
            $result = $event |  where { ($_.message -match ".*mimikatz.*" -or $_.message -match ".*mimilib.*" -or $_.message -match ".*<3 eo.oe.*" -or $_.message -match ".*eo.oe.kiwi.*" -or $_.message -match ".*privilege::debug.*" -or $_.message -match ".*sekurlsa::logonpasswords.*" -or $_.message -match ".*lsadump::sam.*" -or $_.message -match ".*mimidrv.sys.*" -or $_.message -match ".* p::d .*" -or $_.message -match ".* s::l .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
