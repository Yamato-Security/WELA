# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*verb:sync" -and $_.message -match "CommandLine.*.*-source:RunCommand" -and $_.message -match "CommandLine.*.*-dest:runCommand" -and ($_.message -match "Image.*.*\msdeploy.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_msdeploy";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_msdeploy";
            $detectedMessage = "Detects file execution using the msdeploy.exe lolbin";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*verb:sync" -and $_.message -match "CommandLine.*.*-source:RunCommand" -and $_.message -match "CommandLine.*.*-dest:runCommand" -and ($_.message -match "Image.*.*\msdeploy.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
