# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.* /lockscreenurl:.*" -and  -not (($_.message -match "CommandLine.*.*.jpg.*" -or $_.message -match "CommandLine.*.*.jpeg.*" -or $_.message -match "CommandLine.*.*.png.*"))) -or ($_.message -match "CommandLine.*.*reg delete.*" -and $_.message -match "CommandLine.*.*\PersonalizationCSP.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_desktopimgdownldr";
    $detectedMessage = "Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.* /lockscreenurl:.*" -and -not (($_.message -match "CommandLine.*.*.jpg.*" -or $_.message -match "CommandLine.*.*.jpeg.*" -or $_.message -match "CommandLine.*.*.png.*"))) -or ($_.message -match "CommandLine.*.*reg delete.*" -and $_.message -match "CommandLine.*.*\PersonalizationCSP.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
