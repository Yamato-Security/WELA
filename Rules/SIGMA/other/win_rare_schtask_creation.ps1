# Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | where {($_.ID -eq "106") }  | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_rare_schtask_creation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rare_schtask_creation";
            $detectedMessage = "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.";
            $result = $event |  where { ($_.ID -eq "106") } | group-object TaskName | where { $_.count -lt 5 } | select name, count | sort -desc;
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
