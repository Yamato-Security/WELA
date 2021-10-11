# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\.*" -and $_.message -match "TargetObject.*.*_Classes\exefile\shell\runas\command\isolatedCommand") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_uac_bypass_sdclt";
    $detectedMessage = "Detects changes to HKCU:SoftwareClassesexefileshell
unasmmandisolatedCommand"

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_uac_bypass_sdclt";
            $detectedMessage = "Detects changes to HKCU:SoftwareClassesexefileshell"
            $result = $event |  where { ($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\\.*" -and $_.message -match "TargetObject.*.*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand" } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
