# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*rundll32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rundll32_without_parameters";
    $detectedMessage = "Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*rundll32.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}