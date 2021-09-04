# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*http.*" -and $_.message -match "CommandLine.*.*://.*" -and $_.message -match "CommandLine.*.*%AppData%.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_cmd_http_appdata";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
