# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "CommandLine.*.*transport=dt_socket,address=" -and  -not ($_.message -match "CommandLine.*.*address=127.0.0.1" -or $_.message -match "CommandLine.*.*address=localhost")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_vul_java_remote_debugging";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_vul_java_remote_debugging";
            $detectedMessage = "Detects a JAVA process running with remote debugging allowing more than just localhost to connect";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "CommandLine.*.*transport=dt_socket,address=" -and -not ($_.message -match "CommandLine.*.*address=127.0.0.1" -or $_.message -match "CommandLine.*.*address=localhost")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
