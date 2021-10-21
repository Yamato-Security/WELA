# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\\powershell.exe" -and  -not (($_.message -match "ParentImage.*.*\\explorer.exe" -or $_.message -match "ParentImage.*.*\\CompatTelRunner.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_non_interactive_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_non_interactive_powershell";
            $detectedMessage = "Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "Image.*.*\\powershell.exe" -and -not (($_.message -match "ParentImage.*.*\\explorer.exe" -or $_.message -match "ParentImage.*.*\\CompatTelRunner.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
