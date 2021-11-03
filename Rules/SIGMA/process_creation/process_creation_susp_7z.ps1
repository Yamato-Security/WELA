# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*7z.exe" -or $_.message -match "CommandLine.*.*7za.exe") -and $_.message -match "CommandLine.*.* -p" -and ($_.message -match "CommandLine.*.* a " -or $_.message -match "CommandLine.*.* u ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_7z";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_susp_7z";
            $detectedMessage = "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*7z.exe" -or $_.message -match "CommandLine.*.*7za.exe") -and $_.message -match "CommandLine.*.* -p" -and ($_.message -match "CommandLine.*.* a " -or $_.message -match "CommandLine.*.* u ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
