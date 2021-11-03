# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*.doc" -or $_.message -match "ScriptBlockText.*.*.docx" -or $_.message -match "ScriptBlockText.*.*.xls" -or $_.message -match "ScriptBlockText.*.*.xlsx" -or $_.message -match "ScriptBlockText.*.*.ppt" -or $_.message -match "ScriptBlockText.*.*.pptx" -or $_.message -match "ScriptBlockText.*.*.rtf" -or $_.message -match "ScriptBlockText.*.*.pdf" -or $_.message -match "ScriptBlockText.*.*.txt") -and $_.message -match "ScriptBlockText.*.*Get-ChildItem" -and $_.message -match "ScriptBlockText.*.* -Recurse " -and $_.message -match "ScriptBlockText.*.* -Include ") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_automated_collection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_automated_collection";
            $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data.";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*.doc" -or $_.message -match "ScriptBlockText.*.*.docx" -or $_.message -match "ScriptBlockText.*.*.xls" -or $_.message -match "ScriptBlockText.*.*.xlsx" -or $_.message -match "ScriptBlockText.*.*.ppt" -or $_.message -match "ScriptBlockText.*.*.pptx" -or $_.message -match "ScriptBlockText.*.*.rtf" -or $_.message -match "ScriptBlockText.*.*.pdf" -or $_.message -match "ScriptBlockText.*.*.txt") -and $_.message -match "ScriptBlockText.*.*Get-ChildItem" -and $_.message -match "ScriptBlockText.*.* -Recurse " -and $_.message -match "ScriptBlockText.*.* -Include ") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
