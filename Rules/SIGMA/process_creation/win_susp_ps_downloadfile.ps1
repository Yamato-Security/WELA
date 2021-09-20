# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ps_downloadfile";
    $detectedMessage = "Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
