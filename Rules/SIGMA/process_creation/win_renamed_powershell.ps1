# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Description.*Windows PowerShell.*" -or $_.message -match "Description.*pwsh.*") -and $_.message -match "Company.*Microsoft Corporation") -and  -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe" -or $_.message -match "Image.*.*\\pwsh.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_powershell";
            $detectedMessage = "Detects the execution of a renamed PowerShell often used by attackers or malware";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Description.*Windows PowerShell.*" -or $_.message -match "Description.*pwsh.*") -and $_.message -match "Company.*Microsoft Corporation") -and -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe" -or $_.message -match "Image.*.*\\pwsh.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
