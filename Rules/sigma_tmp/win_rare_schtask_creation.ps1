# Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | where {($_.ID -eq "106") }  | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_rare_schtask_creation";
    $detectedMessage = "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "106") } | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc;
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
