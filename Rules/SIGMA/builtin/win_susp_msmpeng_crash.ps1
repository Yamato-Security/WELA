# Get-WinEvent -LogName Application | where {((($_.message -match "Source.*Application Error" -and $_.ID -eq "1000") -or ($_.message -match "Source.*Windows Error Reporting" -and $_.ID -eq "1001")) -and ($_.message -match ".*MsMpEng.exe.*" -or $_.message -match ".*mpengine.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_msmpeng_crash";
    $detectedMessage = "This rule detects a suspicious crash of the Microsoft Malware Protection Engine";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.message -match "Source.*Application Error" -and $_.ID -eq "1000") -or ($_.message -match "Source.*Windows Error Reporting" -and $_.ID -eq "1001")) -and ($_.message -match ".*MsMpEng.exe.*" -or $_.message -match ".*mpengine.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
