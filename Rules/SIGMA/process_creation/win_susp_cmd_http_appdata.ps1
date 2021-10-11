# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*http.*" -and $_.message -match "CommandLine.*.*://.*" -and $_.message -match "CommandLine.*.*%AppData%.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_cmd_http_appdata";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_cmd_http_appdata";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*http.*" -and $_.message -match "CommandLine.*.*://.*" -and $_.message -match "CommandLine.*.*%AppData%.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
