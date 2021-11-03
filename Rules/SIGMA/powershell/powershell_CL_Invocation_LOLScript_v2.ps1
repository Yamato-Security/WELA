# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*CL_Invocation.ps1" -or $_.message -match "ScriptBlockText.*.*SyncInvoke")) }  | select Computer, ScriptBlockText | group Computer | foreach { [PSCustomObject]@{'Computer'=$_.name;'Count'=($_.group.ScriptBlockText | sort -u).count} }  | sort count -desc | where { $_.count -gt 2 }

function Add-Rule {

    $ruleName = "powershell_CL_Invocation_LOLScript_v2";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_CL_Invocation_LOLScript_v2";
            $detectedMessage = "Detects Execution via SyncInvoke in CL_Invocation.ps1 module";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*CL_Invocation.ps1" -or $_.message -match "ScriptBlockText.*.*SyncInvoke")) } | select Computer, ScriptBlockText | group Computer | foreach { [PSCustomObject]@{'Computer' = $_.name; 'Count' = ($_.group.ScriptBlockText | sort -u).count } } | sort count -desc | where { $_.count -gt 2 };
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
