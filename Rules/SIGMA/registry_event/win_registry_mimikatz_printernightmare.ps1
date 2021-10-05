# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\QMS 810\\.*" -or $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\mimikatz.*") -or ($_.message -match "TargetObject.*.*legitprinter.*" -and $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows.*")) -or (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\Control\\Print\\Environments.*" -or $_.message -match "TargetObject.*.*\\CurrentVersion\\Print\\Printers.*") -and ($_.message -match "TargetObject.*.*Gentil Kiwi.*" -or $_.message -match "TargetObject.*.*mimikatz printer.*" -or $_.message -match "TargetObject.*.*Kiwi Legit Printer.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_registry_mimikatz_printernightmare";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_registry_mimikatz_printernightmare";
            $detectedMessage = "Detects static QMS 810 and mimikatz driver name used by Mimikatz as exploited in CVE-2021-1675 and CVE-2021-34527";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\QMS 810\\.*" -or $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\mimikatz.*") -or ($_.message -match "TargetObject.*.*legitprinter.*" -and $_.message -match "TargetObject.*.*\\Control\\Print\\Environments\\Windows.*")) -or (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\Control\\Print\\Environments.*" -or $_.message -match "TargetObject.*.*\\CurrentVersion\\Print\\Printers.*") -and ($_.message -match "TargetObject.*.*Gentil Kiwi.*" -or $_.message -match "TargetObject.*.*mimikatz printer.*" -or $_.message -match "TargetObject.*.*Kiwi Legit Printer.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
