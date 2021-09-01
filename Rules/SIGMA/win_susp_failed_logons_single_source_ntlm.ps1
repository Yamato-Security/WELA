# Get-WinEvent -LogName Security | where {(($_.ID -eq "4776" -and $_.message -match "Status.*.*0xC000006A") -and  -not ($_.message -match "TargetUserName.*.*$")) }  | select Workstation, TargetUserName | group Workstation | foreach { [PSCustomObject]@{'Workstation'=$_.name;'Count'=($_.group.TargetUserName | sort -u).count} }  | sort count -desc | where { $_.count -gt 10 }

function Add-Rule {
    param (
        [hashtable] $stack,
        [bool] $isLiveAnalysis
    )
    if ($isLiveAnalysis) {
        # LiveAnalysysが必要か確認する
    }
    else {
        $detectRule = {
            $ruleName = "win_susp_failed_logons_single_source_ntlm";
            function Search-DetectableEvents {
                param (
                    $event
                )
                $result = $event | where { (($_.ID -eq "4776" -and $_.message -match "Status.*.*0xC000006A") -and -not ($_.message -match "TargetUserName.*.*$")) }  | select Workstation, TargetUserName | group Workstation | foreach { [PSCustomObject]@{'Workstation' = $_.name; 'Count' = ($_.group.TargetUserName | sort -u).count } }  | sort count -desc | where { $_.count -gt 10 };
                Write-Host $result;
                # if $result.Count -ne 0 {
                #     # detect時のcount処理が必要であればここで処理？
                # }
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
            }
            Search-DetectableEvents $args[0]
        }
    } 
    $stack.Insert('win_susp_failed_logons_single_source_ntlm', $detectRule);
}

Add-Rule