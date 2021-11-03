# Get-WinEvent -LogName Security | where {($_.ID -eq "4663" -and $_.message -match "ObjectType.*File" -and $_.message -match "AccessList.*%%1537" -and $_.message -match "Keywords.*0x8020000000000000") }  | group-object SubjectLogonId | where { $_.count -gt 10 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_susp_multiple_files_renamed_or_deleted";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_multiple_files_renamed_or_deleted";
            $detectedMessage = "Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity).";
            $result = $event |  where { ($_.ID -eq "4663" -and $_.message -match "ObjectType.*File" -and $_.message -match "AccessList.*%%1537" -and $_.message -match "Keywords.*0x8020000000000000") } | group-object SubjectLogonId | where { $_.count -gt 10 } | select name, count | sort -desc;
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
