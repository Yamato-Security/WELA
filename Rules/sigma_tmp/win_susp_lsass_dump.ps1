# Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ProcessName.*.*\lsass.exe" -and $_.message -match "AccessMask.*0x705" -and $_.message -match "ObjectType.*SAM_DOMAIN") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_lsass_dump";
    $detectedMessage = "Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4656" -and $_.message -match "ProcessName.*.*\lsass.exe" -and $_.message -match "AccessMask.*0x705" -and $_.message -match "ObjectType.*SAM_DOMAIN") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}