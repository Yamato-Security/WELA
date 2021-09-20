# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*/i:%APPDATA%\logs.txt scrobj.dll") -and (($_.message -match "Image.*.*\cutil.exe") -or ($_.message -match "Microsoft(C) Registerserver"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_empiremonkey";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_apt_empiremonkey";
                    $detectedMessage = "Detects EmpireMonkey APT reported Activity";
                $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*/i:%APPDATA%\\logs.txt scrobj.dll") -and (($_.message -match "Image.*.*\\cutil.exe") -or ($_.message -match "Microsoft(C) Registerserver"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
