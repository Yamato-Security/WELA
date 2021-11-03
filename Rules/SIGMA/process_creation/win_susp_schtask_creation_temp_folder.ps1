# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.* /create " -and $_.message -match "CommandLine.*.* /sc once " -and $_.message -match "CommandLine.*.*\\Temp\\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_schtask_creation_temp_folder";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_schtask_creation_temp_folder";
            $detectedMessage = "Detects the creation of scheduled tasks that involves a temporary folder and runs only once";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.* /create " -and $_.message -match "CommandLine.*.* /sc once " -and $_.message -match "CommandLine.*.*\\Temp\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
