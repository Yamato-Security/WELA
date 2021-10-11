# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -ma .*" -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.* lsass.*") -or $_.message -match "CommandLine.*.* ls.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_procdump_lsass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_procdump_lsass";
                    $detectedMessage = "Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.";
                $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -ma .*" -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.* lsass.*") -or $_.message -match "CommandLine.*.* ls.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
