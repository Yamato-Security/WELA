# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and ($_.message -match "3268" -or $_.message -match "3269")) }  | group-object SourceAddress | where { $_.count -gt 2000 } | select name,count | sort -desc

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_global_catalog_enumeration";
    $detectedMessage = "Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Threshold according to domain width."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5156" -and ($_.message -match "3268" -or $_.message -match "3269")) } | group-object SourceAddress | where { $_.count -gt 2000 } | select name,count | sort -desc;
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
