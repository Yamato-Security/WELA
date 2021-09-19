# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*CL_Mutexverifiers.ps1.*" -or $_.message -match "ScriptBlockText.*.*runAfterCancelProcess.*")) }  | select Computer, ScriptBlockText | group Computer | foreach { [PSCustomObject]@{'Computer'=$_.name;'Count'=($_.group.ScriptBlockText | sort -u).count} }  | sort count -desc | where { $_.count -gt 2 }

function Add-Rule {

    $ruleName = "powershell_CL_Mutexverifiers_LOLScript_v2";
    $detectedMessage = "Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*CL_Mutexverifiers.ps1.*" -or $_.message -match "ScriptBlockText.*.*runAfterCancelProcess.*")) } | select Computer, ScriptBlockText | group Computer | foreach { [PSCustomObject]@{'Computer'=$_.name;'Count'=($_.group.ScriptBlockText | sort -u).count} } | sort count -desc | where { $_.count -gt 2 };
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
