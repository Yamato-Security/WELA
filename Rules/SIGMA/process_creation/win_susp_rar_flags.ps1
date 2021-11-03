# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -hp") -and ($_.message -match "CommandLine.*.* -m" -or $_.message -match "CommandLine.*.* a ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rar_flags";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rar_flags";
            $detectedMessage = "Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -hp") -and ($_.message -match "CommandLine.*.* -m" -or $_.message -match "CommandLine.*.* a ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
