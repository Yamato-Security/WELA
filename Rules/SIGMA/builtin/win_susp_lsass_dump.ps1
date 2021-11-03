# Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ProcessName.*.*\lsass.exe" -and $_.message -match "AccessMask.*0x705" -and $_.message -match "ObjectType.*SAM_DOMAIN") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_lsass_dump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_lsass_dump";
            $detectedMessage = "Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN";
            $result = $event |  where { ($_.ID -eq "4656" -and $_.message -match "ProcessName.*.*\\lsass.exe" -and $_.message -match "AccessMask.*0x705" -and $_.message -match "ObjectType.*SAM_DOMAIN") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
