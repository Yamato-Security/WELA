# Get-WinEvent -LogName Application | where {((($_.message -match "Source.*Application Error" -and $_.ID -eq "1000") -or ($_.message -match "Source.*Windows Error Reporting" -and $_.ID -eq "1001")) -and ($_.message -match "MsMpEng.exe" -or $_.message -match "mpengine.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_msmpeng_crash";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_msmpeng_crash";
            $detectedMessage = "This rule detects a suspicious crash of the Microsoft Malware Protection Engine";
            $result = $event |  where { ((($_.message -match "Source.*Application Error" -and $_.ID -eq "1000") -or ($_.message -match "Source.*Windows Error Reporting" -and $_.ID -eq "1001")) -and ($_.message -match "MsMpEng.exe" -or $_.message -match "mpengine.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
