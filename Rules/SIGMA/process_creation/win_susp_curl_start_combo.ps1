# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*curl.*" -and $_.message -match "CommandLine.*.* start .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_curl_start_combo";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_curl_start_combo";
            $detectedMessage = "Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*curl.*" -and $_.message -match "CommandLine.*.* start .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
