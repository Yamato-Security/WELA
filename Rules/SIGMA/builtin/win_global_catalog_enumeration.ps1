# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and ($_.message -match "3268" -or $_.message -match "3269")) }  | group-object SourceAddress | where { $_.count -gt 2000 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_global_catalog_enumeration";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_global_catalog_enumeration";
            $detectedMessage = "Detects enumeration of the global catalog (that can be performed using BloodHound or others AD reconnaissance tools). Adjust Threshold according to domain width.";
            $result = $event |  where { ($_.ID -eq "5156" -and ($_.message -match "3268" -or $_.message -match "3269")) } | group-object SourceAddress | where { $_.count -gt 2000 } | select name, count | sort -desc;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
