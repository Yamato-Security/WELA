# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*.CreationTime =" -or $_.message -match "ScriptBlockText.*.*.LastWriteTime =" -or $_.message -match "ScriptBlockText.*.*.LastAccessTime =" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetCreationTime" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetLastAccessTime" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetLastWriteTime")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_timestomp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_timestomp";
            $detectedMessage = "Adversaries may modify file time attributes to hide new or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. ";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*.CreationTime =" -or $_.message -match "ScriptBlockText.*.*.LastWriteTime =" -or $_.message -match "ScriptBlockText.*.*.LastAccessTime =" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetCreationTime" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetLastAccessTime" -or $_.message -match "ScriptBlockText.*.*[IO.File]::SetLastWriteTime")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
