# Get-WinEvent -LogName Application | where {($_.ID -eq "4" -and $_.message -match "Source.*MSExchange Control Panel" -and $_.message -match "Level.*Error" -and ($_.message -match ".*&__VIEWSTATE=.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_vul_cve_2020_0688";
    $detectedMessage = "Detects the exploitation of Microsoft Exchange vulnerability as described in CVE-2020-0688 "

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4" -and $_.message -match "Source.*MSExchange Control Panel" -and $_.message -match "Level.*Error" -and ($_.message -match ".*!firstpipe!__VIEWSTATE=.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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