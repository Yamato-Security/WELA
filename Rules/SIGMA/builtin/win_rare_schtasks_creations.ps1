# Get-WinEvent -LogName Security | where {($_.ID -eq "4698") }  | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_rare_schtasks_creations";
    $detectedMessage = "Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4698") } | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc;
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
