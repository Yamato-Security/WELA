# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -version 2 " -or $_.message -match "CommandLine.*.* -versio 2 " -or $_.message -match "CommandLine.*.* -versi 2 " -or $_.message -match "CommandLine.*.* -vers 2 " -or $_.message -match "CommandLine.*.* -ver 2 " -or $_.message -match "CommandLine.*.* -ve 2 ") -and $_.message -match "Image.*.*\\powershell.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_downgrade_attack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_downgrade_attack";
            $detectedMessage = "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -version 2 " -or $_.message -match "CommandLine.*.* -versio 2 " -or $_.message -match "CommandLine.*.* -versi 2 " -or $_.message -match "CommandLine.*.* -vers 2 " -or $_.message -match "CommandLine.*.* -ver 2 " -or $_.message -match "CommandLine.*.* -ve 2 ") -and $_.message -match "Image.*.*\\powershell.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
