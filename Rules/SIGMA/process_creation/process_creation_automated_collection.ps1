# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*.doc" -or $_.message -match "CommandLine.*.*.docx" -or $_.message -match "CommandLine.*.*.xls" -or $_.message -match "CommandLine.*.*.xlsx" -or $_.message -match "CommandLine.*.*.ppt" -or $_.message -match "CommandLine.*.*.pptx" -or $_.message -match "CommandLine.*.*.rtf" -or $_.message -match "CommandLine.*.*.pdf" -or $_.message -match "CommandLine.*.*.txt") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*dir " -and $_.message -match "CommandLine.*.* /b " -and $_.message -match "CommandLine.*.* /s ") -or ($_.message -match "OriginalFileName.*FINDSTR.EXE" -and $_.message -match "CommandLine.*.* /e "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_automated_collection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_automated_collection";
            $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data.";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*.doc" -or $_.message -match "CommandLine.*.*.docx" -or $_.message -match "CommandLine.*.*.xls" -or $_.message -match "CommandLine.*.*.xlsx" -or $_.message -match "CommandLine.*.*.ppt" -or $_.message -match "CommandLine.*.*.pptx" -or $_.message -match "CommandLine.*.*.rtf" -or $_.message -match "CommandLine.*.*.pdf" -or $_.message -match "CommandLine.*.*.txt") -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*dir " -and $_.message -match "CommandLine.*.* /b " -and $_.message -match "CommandLine.*.* /s ") -or ($_.message -match "OriginalFileName.*FINDSTR.EXE" -and $_.message -match "CommandLine.*.* /e "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
