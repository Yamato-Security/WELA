# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\Microsoft.Workflow.Compiler.exe" -or ($_.message -match "OriginalFileName.*Microsoft.Workflow.Compiler.exe" -and $_.message -match "CommandLine.*.*.xml"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_workflow_compiler";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_workflow_compiler";
            $detectedMessage = "Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\Microsoft.Workflow.Compiler.exe" -or ($_.message -match "OriginalFileName.*Microsoft.Workflow.Compiler.exe" -and $_.message -match "CommandLine.*.*.xml"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
