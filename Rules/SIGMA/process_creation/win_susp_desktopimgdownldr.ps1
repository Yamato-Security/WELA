# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.* /lockscreenurl:" -and  -not (($_.message -match "CommandLine.*.*.jpg" -or $_.message -match "CommandLine.*.*.jpeg" -or $_.message -match "CommandLine.*.*.png"))) -or ($_.message -match "CommandLine.*.*reg delete" -and $_.message -match "CommandLine.*.*\\PersonalizationCSP"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_desktopimgdownldr";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_desktopimgdownldr";
            $detectedMessage = "Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet";
            $result = $event | where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "CommandLine.*.* /lockscreenurl:" -and -not (($_.message -match "CommandLine.*.*.jpg" -or $_.message -match "CommandLine.*.*.jpeg" -or $_.message -match "CommandLine.*.*.png"))) -or ($_.message -match "CommandLine.*.*reg delete" -and $_.message -match "CommandLine.*.*\\PersonalizationCSP"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
