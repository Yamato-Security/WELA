# Get-WinEvent -LogName Security | where {($_.ID -eq "4663" -and $_.message -match "ObjectType.*File" -and $_.message -match "AccessList.*%%1537" -and $_.message -match "Keywords.*0x8020000000000000") }  | group-object SubjectLogonId | where { $_.count -gt 10 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_susp_multiple_files_renamed_or_deleted";
    $detectedMessage = "Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity).";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4663" -and $_.message -match "ObjectType.*File" -and $_.message -match "AccessList.*%%1537" -and $_.message -match "Keywords.*0x8020000000000000") } | group-object SubjectLogonId | where { $_.count -gt 10 } | select name,count | sort -desc;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
