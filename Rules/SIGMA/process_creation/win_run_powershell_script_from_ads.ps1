# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Content" -and $_.message -match "CommandLine.*.*-Stream") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_run_powershell_script_from_ads";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_run_powershell_script_from_ads";
            $detectedMessage = "Detects PowerShell script execution from Alternate Data Stream (ADS)";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Content" -and $_.message -match "CommandLine.*.*-Stream") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
