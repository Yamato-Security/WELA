# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\bginfo.exe" -and $_.message -match "CommandLine.*.*/popup.*" -and $_.message -match "CommandLine.*.*/nolicprompt.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_bginfo";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_bginfo";
                    $detectedMessage = "Execute VBscript code that is referenced within the *.bgi file.";
                $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\bginfo.exe" -and $_.message -match "CommandLine.*.*/popup.*" -and $_.message -match "CommandLine.*.*/nolicprompt.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
