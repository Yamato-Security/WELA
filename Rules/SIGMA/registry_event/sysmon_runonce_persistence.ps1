# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components.*" -and $_.message -match "TargetObject.*.*\StubPath") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_runonce_persistence";
    $detectedMessage = "Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components.*" -and $_.message -match "TargetObject.*.*\StubPath") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
(.*)Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}