# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ps_downloadfile";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ps_downloadfile";
            $detectedMessage = "Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
