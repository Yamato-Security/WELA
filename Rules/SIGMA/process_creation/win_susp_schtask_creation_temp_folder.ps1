# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.* /create .*" -and $_.message -match "CommandLine.*.* /sc once .*" -and $_.message -match "CommandLine.*.*\Temp\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_schtask_creation_temp_folder";
    $detectedMessage = "Detects the creation of scheduled tasks that involves a temporary folder and runs only once";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.* /create .*" -and $_.message -match "CommandLine.*.* /sc once .*" -and $_.message -match "CommandLine.*.*\Temp\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
