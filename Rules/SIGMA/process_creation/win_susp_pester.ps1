# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Pester" -and $_.message -match "CommandLine.*.*Get-Help") -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*pester" -and $_.message -match "CommandLine.*.*;" -and ($_.message -match "CommandLine.*.*help" -or $_.message -match "CommandLine.*.*?")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_pester";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_pester";
            $detectedMessage = "Detects code execution via Pester.bat (Pester - Powershell Modulte for testing) ";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Pester" -and $_.message -match "CommandLine.*.*Get-Help") -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*pester" -and $_.message -match "CommandLine.*.*;" -and ($_.message -match "CommandLine.*.*help" -or $_.message -match "CommandLine.*.*?")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
