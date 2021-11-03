# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*InfDefaultInstall.exe " -and $_.message -match "CommandLine.*.*.inf") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_infdefaultinstall";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_infdefaultinstall";
            $detectedMessage = "Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*InfDefaultInstall.exe " -and $_.message -match "CommandLine.*.*.inf") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
