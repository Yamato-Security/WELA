# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"" -or $_.message -match "CommandLine.*powershell.exe mshta.exe http.*" -or $_.message -match "cmd.exe /c taskkill /im cmd.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_babyshark";
    $detectedMessage = "Detects activity that could be related to Baby Shark malware";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "reg query ""HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default""" -or $_.message -match "CommandLine.*powershell.exe mshta.exe http.*" -or $_.message -match "cmd.exe /c taskkill /im cmd.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
